// Copyright 2021 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package rawdb

import (
	"bytes"
	"fmt"
	"sync/atomic"

	"github.com/ethereum/go-ethereum/common/math"
	"github.com/ethereum/go-ethereum/rlp"
)

// freezerBatch is a write operation of multiple items on a freezer.
type freezerBatch struct {
	f      *freezer
	tables map[string]*freezerTableBatch
}

func newFreezerBatch(f *freezer) *freezerBatch {
	batch := &freezerBatch{
		f:      f,
		tables: make(map[string]*freezerTableBatch, len(f.tables)),
	}
	for kind, table := range f.tables {
		batch.tables[kind] = table.newBatch()
	}
	return batch
}

// Append adds an RLP-encoded item of the given kind.
func (batch *freezerBatch) Append(kind string, num uint64, item interface{}) error {
	return batch.tables[kind].Append(num, item)
}

// AppendRaw adds an item of the given kind.
func (batch *freezerBatch) AppendRaw(kind string, num uint64, item []byte) error {
	return batch.tables[kind].AppendRaw(num, item)
}

func (batch *freezerBatch) Commit() error {
	// Check that count agrees on all batches.
	count := -1
	for name, tb := range batch.tables {
		if count >= 0 && tb.count != count {
			return fmt.Errorf("batch %s has count %d, want %d", name, tb.count, count)
		}
		count = tb.count
	}

	// Commit all table batches.
	for _, tb := range batch.tables {
		if err := tb.Commit(); err != nil {
			return err
		}
	}

	// Bump frozen block index.
	atomic.AddUint64(&batch.f.frozen, uint64(count))
	return nil
}

// freezerTableBatch is a batch for a freezer table.
type freezerTableBatch struct {
	t   *freezerTable
	buf bytes.Buffer
	sb  *BufferedSnapWriter

	firstIdx uint64
	count    int
	sizes    []uint32

	headBytes uint32
}

// newBatch creates a new batch for the freezer table.
func (t *freezerTable) newBatch() *freezerTableBatch {
	batch := &freezerTableBatch{
		t:        t,
		firstIdx: math.MaxUint64,
	}
	if !t.noCompression {
		batch.sb = new(BufferedSnapWriter)
	}
	return batch
}

// Reset clears the batch for reuse.
func (batch *freezerTableBatch) Reset() {
	batch.firstIdx = math.MaxUint64
	batch.buf.Reset()
	if batch.sb != nil {
		batch.sb.Reset()
	}
	batch.count = 0
	batch.sizes = batch.sizes[:0]
	batch.headBytes = 0
}

// Append rlp-encodes and adds data at the end of the freezer table. The item number is a
// precautionary parameter to ensure data correctness, but the table will reject already
// existing data.
func (batch *freezerTableBatch) Append(item uint64, data interface{}) error {
	if batch.firstIdx == math.MaxUint64 {
		batch.firstIdx = item
	}
	if have, want := item, batch.firstIdx+uint64(batch.count); have != want {
		return fmt.Errorf("appending unexpected item: want %d, have %d", want, have)
	}
	s0 := batch.buf.Len()
	if batch.sb != nil {
		// RLP-encode
		if err := rlp.Encode(batch.sb, data); err != nil {
			return err
		}
		// Snappy-encode to our buf
		if err := batch.sb.WriteTo(&batch.buf); err != nil {
			return err
		}
	} else {
		if err := rlp.Encode(&batch.buf, data); err != nil {
			return err
		}
	}
	s1 := batch.buf.Len()
	batch.sizes = append(batch.sizes, uint32(s1-s0))
	batch.count++
	return nil
}

// AppendRaw injects a binary blob at the end of the freezer table. The item number is a
// precautionary parameter to ensure data correctness, but the table will reject already
// existing data.
func (batch *freezerTableBatch) AppendRaw(item uint64, blob []byte) error {
	if batch.firstIdx == math.MaxUint64 {
		batch.firstIdx = item
	}
	if have, want := item, batch.firstIdx+uint64(batch.count); have != want {
		return fmt.Errorf("appending unexpected item: want %d, have %d", want, have)
	}
	s0 := batch.buf.Len()
	if batch.sb != nil {
		if err := batch.sb.WriteDirectTo(&batch.buf, blob); err != nil {
			return err
		}
	} else {
		if _, err := batch.buf.Write(blob); err != nil {
			return err
		}
	}
	s1 := batch.buf.Len()
	batch.sizes = append(batch.sizes, uint32(s1-s0))
	batch.count++
	return nil
}

// Write writes the batched items to the backing freezerTable.
func (batch *freezerTableBatch) Commit() error {
	var (
		retry = false
		err   error
	)
	for {
		retry, err = batch.write(retry)
		if err != nil {
			return err
		}
		if !retry {
			return nil
		}
	}
}

// write is the internal implementation which writes the batch to the backing
// table. It will only ever write as many items as fits into one table: if
// the backing table needs to open a new file, this method will return with a
// (true, nil), to signify that it needs to be invoked again.
func (batch *freezerTableBatch) write(newHead bool) (bool, error) {
	if !newHead {
		batch.t.lock.RLock()
		defer batch.t.lock.RUnlock()
	} else {
		batch.t.lock.Lock()
		defer batch.t.lock.Unlock()
	}
	if batch.t.index == nil || batch.t.head == nil {
		return false, errClosed
	}

	// Ensure we're in sync with the data
	if atomic.LoadUint64(&batch.t.items) != batch.firstIdx {
		return false, fmt.Errorf("appending unexpected item: want %d, have %d", batch.t.items, batch.firstIdx)
	}
	if newHead {
		if err := batch.t.advanceHead(); err != nil {
			return false, err
		}
		// And update the batch to point to the new file
		batch.headBytes = 0
	}
	var (
		filenum         = atomic.LoadUint32(&batch.t.headId)
		indexData       = make([]byte, 0, len(batch.sizes)*indexEntrySize)
		count           int
		writtenDataSize int
	)
	for _, size := range batch.sizes {
		if batch.headBytes+size <= batch.t.maxFileSize {
			writtenDataSize += int(size)
			idx := indexEntry{
				filenum: filenum,
				offset:  batch.headBytes + size,
			}
			batch.headBytes += size
			idxData := idx.marshallBinary()
			indexData = append(indexData, idxData...)
		} else {
			// Writing will overflow, need to chunk up the batch into several writes
			break
		}
		count++
	}
	if writtenDataSize == 0 {
		return batch.count > 0, nil
	}
	// Write the actual data
	if _, err := batch.t.head.Write(batch.buf.Next(writtenDataSize)); err != nil {
		return false, err
	}
	// Write the new indexdata
	if _, err := batch.t.index.Write(indexData); err != nil {
		return false, err
	}
	batch.t.writeMeter.Mark(int64(batch.buf.Len()) + int64(batch.count)*int64(indexEntrySize))
	batch.t.sizeGauge.Inc(int64(batch.buf.Len()) + int64(batch.count)*int64(indexEntrySize))
	atomic.AddUint64(&batch.t.items, uint64(count))
	batch.firstIdx += uint64(count)
	batch.count -= count

	if batch.count > 0 {
		// Some data left to write on a retry.
		batch.sizes = batch.sizes[count:]
		return true, nil
	}
	// All data written. We can simply truncate and keep using the buffer
	batch.sizes = batch.sizes[:0]
	return false, nil
}

func (batch *freezerTableBatch) Size() int {
	return batch.buf.Len()
}
