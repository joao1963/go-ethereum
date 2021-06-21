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

package core

import (
	"math/big"
	"sort"
	"sync"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethdb"
)

// hdrInfo is a linked list of abbreviated header information.
type hdrInfo struct {
	parent *hdrInfo    // parent header
	td     *big.Int    // total difficulty of this header
	hash   common.Hash // header hash
	number uint64      // header number
}

// getHeader returns the head at the given number, and also whether it's the same as current
func (info *hdrInfo) getHeader(number uint64) (*hdrInfo, bool) {
	if number > info.number {
		return nil, false
	}
	elem := info
	for elem.number > number {
		elem = elem.parent
	}
	return elem, elem == info
}

// trim deletes the elements before the threshold, and returns the tip of the removed
// chain
func (info *hdrInfo) trim(threshold uint64) *hdrInfo {
	if threshold > info.number {
		return nil
	}
	elem := info
	for elem.number > threshold {
		elem = elem.parent
	}
	tailTip := elem.parent
	elem.parent = nil
	return tailTip
}

func (info *hdrInfo) forEach(onInfo func(*hdrInfo) bool) {
	elem := info
	for elem != nil && onInfo(elem) {
		elem = elem.parent
	}
}

// extend adds the given blocks to the linked list. It assumes the headers
// are linked internally and also properly linked to the hdrInfo they're being
// appended to. This method returns the new tip of the chain.
func (info *hdrInfo) extend(headers []*types.Header) *hdrInfo {
	if info.hash != headers[0].ParentHash {
		panic("Extending on non-child")
	}
	parent := info
	for i, hdr := range headers[:len(headers)-1] {
		td := new(big.Int).Set(parent.td)
		elem := &hdrInfo{
			parent: parent,
			td:     td.Add(td, hdr.Difficulty),
			hash:   headers[i+1].ParentHash,
			number: hdr.Number.Uint64(),
		}
		parent = elem
	}
	last := headers[len(headers)-1]
	td := new(big.Int).Set(parent.td)
	return &hdrInfo{
		parent: parent,
		td:     td.Add(td, last.Difficulty),
		hash:   last.Hash(),
		number: last.Number.Uint64(),
	}
}

// headByTd allows to sort chain tips by total difficulty.
type headByTd []*hdrInfo

func (t headByTd) Len() int           { return len(t) }
func (t headByTd) Less(i, j int) bool { return t[i].td.Cmp(t[j].td) < 0 }
func (t headByTd) Swap(i, j int)      { t[i], t[j] = t[j], t[i] }

type headerDB struct {
	heads     []*hdrInfo
	all       map[common.Hash]*types.Header
	threshold uint64 // Lowest number kept in headerdb.
	mu        sync.RWMutex
}

func NewHeaderDB(genesis *types.Header) *headerDB {
	all := make(map[common.Hash]*types.Header)
	all[genesis.Hash()] = genesis
	return &headerDB{
		heads: []*hdrInfo{
			&hdrInfo{
				parent: nil,
				td:     genesis.Difficulty,
				hash:   genesis.Hash(),
			},
		},
		all: all,
	}
}

func (h *headerDB) WriteHeaders(headers []*types.Header) (result *headerWriteResult, err error) {
	if len(headers) == 0 {
		return &headerWriteResult{}, nil
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	hashOf := func(i int) common.Hash {
		if i < len(headers)-1 {
			return headers[i+1].ParentHash
		}
		return headers[i].Hash()
	}
	// Skip any that we already have
	start := sort.Search(len(headers), func(i int) bool {
		_, known := h.all[hashOf(i)]
		return !known
	})
	if start == len(headers) {
		// All headers known already
		return &headerWriteResult{
			status:   NonStatTy,
			ignored:  len(headers),
			imported: 0,
		}, nil
	}
	prevTd := h.heads[0].td
	// Find which chain it belongs to
	first := headers[start]
	var newTip *hdrInfo
	for i, tip := range h.heads {
		maybeParent, isTip := tip.getHeader(first.Number.Uint64() - 1)
		if maybeParent == nil {
			continue
		}
		if maybeParent.hash != first.ParentHash {
			continue
		}
		parent := maybeParent
		newTip = parent.extend(headers[start:])
		// If we extended the existing tip, we can just replace it. Otherwise,
		// we now have a new tip to track.
		if isTip {
			h.heads[i] = newTip
		} else {
			h.heads = append(h.heads, newTip)
		}
		// Stash the headers
		for j, header := range headers[start:] {
			h.all[hashOf(j)] = header
		}
		break
	}
	if newTip == nil {
		return &headerWriteResult{}, consensus.ErrUnknownAncestor
	}
	// Now, order the tips by TD
	sort.Sort(sort.Reverse(headByTd(h.heads)))
	status := SideStatTy
	if newTip.td.Cmp(prevTd) > 0 {
		// We extended the canon chain
		status = CanonStatTy
	}
	return &headerWriteResult{
		status:     status,
		ignored:    start,
		imported:   len(headers) - start,
		lastHash:   newTip.hash,
		lastHeader: headers[len(headers)-1],
	}, nil
}

func (h *headerDB) GetCurrentHeadHash() common.Hash {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.heads[0].hash
}

// CurrentHeader retrieves the current head header of the canonical chain.
func (h *headerDB) CurrentHeader() *types.Header {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.all[h.heads[0].hash]
}

// GetTd retrieves a block's total difficulty in the canonical chain from the
// database by hash and number.
func (h *headerDB) GetTd(hash common.Hash, number uint64) *big.Int {
	h.mu.RLock()
	defer h.mu.RUnlock()
	// Do we even have the header?
	if h.all[hash] == nil {
		return nil
	}
	// We only need to answer for the canonical chain
	canonTip := h.heads[0]
	if info, _ := canonTip.getHeader(number); info != nil && info.hash == hash {
		// Found it
		return new(big.Int).Set(info.td)
	}
	return nil
}

// GetTdByHash retrieves a block's total difficulty in the canonical chain from the
// database by hash.
func (h *headerDB) GetTdByHash(hash common.Hash) *big.Int {
	h.mu.RLock()
	defer h.mu.RUnlock()
	// Do we even have the header?
	header, ok := h.all[hash]
	if !ok {
		return nil
	}
	// We only need to answer for the canonical chain
	canonTip := h.heads[0]
	if info, _ := canonTip.getHeader(header.Number.Uint64()); info != nil && info.hash == hash {
		// Found it
		return new(big.Int).Set(info.td)
	}
	return nil
}

// GetHeader retrieves a block header from the db by hash and number.
func (h *headerDB) GetHeader(hash common.Hash, number uint64) *types.Header {
	return h.GetHeaderByHash(hash)
}

func (h *headerDB) GetHeaderByNumber(number uint64, chainDb ethdb.Reader) *types.Header {
	h.mu.RLock()
	defer h.mu.RUnlock()
	if number >= h.threshold {
		info, _ := h.heads[0].getHeader(number)
		if info == nil {
			return nil
		}
		return h.all[info.hash]
	}
	hash := rawdb.ReadCanonicalHash(chainDb, number)
	if hash == (common.Hash{}) {
		return nil
	}
	return rawdb.ReadHeader(chainDb, hash, number)
}

func (h *headerDB) GetHeaderByHash(hash common.Hash) *types.Header {
	h.mu.RLock()
	defer h.mu.RUnlock()
	// Do we even have the header?
	return h.all[hash]
}

// GetCanonicalHash returns the canonical hash for the given number.
func (h *headerDB) GetCanonicalHash(number uint64) common.Hash {
	h.mu.RLock()
	defer h.mu.RUnlock()
	info, _ := h.heads[0].getHeader(number)
	if info == nil {
		return common.Hash{}
	}
	return info.hash
}

// Trim causes headers before the given threshold to be forgotten.
func (h *headerDB) Trim(threshold uint64) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, tip := range h.heads {
		tail := tip.trim(threshold)
		tail.forEach(func(deleted *hdrInfo) bool {
			delete(h.all, deleted.hash)
			return true // continue iterating
		})
	}
	h.threshold = threshold
}

// Size returns the approximate size in bytes of memory held
func (h *headerDB) Size() int {
	h.mu.RLock()
	defer h.mu.RUnlock()
	numHeaders := len(h.all)
	size := numHeaders * (540 + 8 + 32) // header size + pointer size + key size
	for _, tip := range h.heads {
		tip.forEach(func(info *hdrInfo) bool {
			size += 64  // 56 + ~8bytes for td bigint
			return true // continue iterating
		})
	}
	return size
}

// Count returns the number of headers being tracked.
func (h *headerDB) Count() int {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return len(h.all)
}
