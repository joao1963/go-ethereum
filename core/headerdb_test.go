package core

import (
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
)

func mkHeader(seed int, parent *types.Header) *types.Header {
	var pHash common.Hash
	var num int64
	if parent != nil {
		pHash = parent.Hash()
		num = int64(parent.Number.Uint64() + 1)
	}
	return &types.Header{
		ParentHash: pHash,
		Difficulty: big.NewInt(20),
		Number:     big.NewInt(int64(num)),
		GasLimit:   uint64(seed),
		GasUsed:    0,
		Time:       uint64(num),
		Extra:      nil,
		MixDigest:  common.Hash{},
		Nonce:      types.BlockNonce{},
		BaseFee:    nil,
	}
}

func mkChain(parent *types.Header, seed, count int) (chain []*types.Header) {
	for i := 0; i < count; i++ {
		parent = mkHeader(seed, parent)
		chain = append(chain, parent)
	}
	return chain
}
func TestMultiChains(t *testing.T) {
	genesis := &types.Header{
		Difficulty: big.NewInt(123),
		Number:     big.NewInt(0),
	}

	headerdb := NewHeaderDB(genesis)

	var chainA = mkChain(genesis, 0, 8)
	if stat, err := headerdb.WriteHeaders(chainA); stat.imported != len(chainA) {
		t.Fatalf("imported %d, expected %d (err: %v)", stat.imported, len(chainA), err)
	}
	// Double import same batch
	if stat, err := headerdb.WriteHeaders(chainA); stat.imported != 0 {
		t.Fatalf("imported %d, expected %d (err: %v)", stat.imported, 0, err)
	}
	// Longer chain
	var chainB = mkChain(genesis, 1, 11)
	if stat, _ := headerdb.WriteHeaders(chainB); stat.imported != len(chainB) {
		t.Fatalf("imported %d, expected %d", stat.imported, len(chainB))
	}
	// Shorter sidechain
	var chainC = mkChain(genesis, 2, 9)
	if stat, _ := headerdb.WriteHeaders(chainC); stat.imported != len(chainC) {
		t.Fatalf("imported %d, expected %d", stat.imported, len(chainC))
	}
	if have, want := headerdb.GetCurrentHeadHash(), chainB[len(chainB)-1].Hash(); have != want {
		t.Fatalf("have %x, want %x", have, want)
	}
	if have, want := headerdb.Count(), 1+8+11+9; have != want {
		t.Fatalf("expected %d items tracked, want %d", have, want)
	}
	t.Logf("size: %v\n", headerdb.Size())
	headerdb.Trim(1)
	if have, want := headerdb.Count(), 0+8+11+9; have != want {
		t.Fatalf("expected %d items tracked, want %d", have, want)
	}
	// hdr 0 should now be gone
	if got := headerdb.GetHeader(genesis.Hash(), 0); got != nil {
		t.Fatalf("expected header to be gone: %v", got)
	}
	// hdr 1 should still exist
	if got := headerdb.GetHeader(chainB[0].Hash(), 1); got == nil {
		t.Fatalf("expected header to be present: %v", chainB[0].Number)
	}
}
