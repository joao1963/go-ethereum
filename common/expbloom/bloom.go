package bloom

import (
	"hash"
	"time"

	bloomfilter "github.com/holiman/bloomfilter/v2"
	"sync/atomic"
)

const (
	k = 4
)

type ExpiringBloom struct {
	currentBloom atomic.Uint64
	blooms       []*bloomfilter.Filter
}

func NewExpiringBloom(n, m uint64, timeout time.Duration) (*ExpiringBloom, error) {
	blooms := make([]*bloomfilter.Filter, 0, n)
	if filter, err := bloomfilter.New(m*8, k); err != nil {
		return nil, err
	} else {
		blooms = append(blooms, filter)
	}
	for i := 0; i < int(n); i++ {
		filter, err := blooms[0].NewCompatible()
		if err != nil {
			return nil, err
		}
		blooms = append(blooms, filter)
	}
	return &ExpiringBloom{blooms: blooms}, nil
}

func (e *ExpiringBloom) tick() {
	// Advance the current bloom
	e.currentBloom.Store((e.currentBloom.Load() + 1) % uint64(len(e.blooms)))
	e.blooms[int(e.currentBloom.Load())].Clear() // Clear it
}

func (e *ExpiringBloom) Add(key hash.Hash64) {
	e.blooms[e.currentBloom.Load()].Add(key)
}

func (e *ExpiringBloom) Contains(key hash.Hash64) bool {
	for _, bloom := range e.blooms {
		if bloom.Contains(key) {
			return true
		}
	}
	return false
}
