// Copyright 2023 The go-ethereum Authors
// This file is part of go-ethereum.
//
// go-ethereum is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// go-ethereum is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with go-ethereum. If not, see <http://www.gnu.org/licenses/>.

package utils

import (
	"fmt"
	"io"
	"math/big"
	"os"
	"path"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus/ethash"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/internal/era"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/trie"
)

var (
	count uint64 = 128
	step  uint64 = 16
)

func TestHistoryExporter(t *testing.T) {
	var (
		key, _  = crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
		address = crypto.PubkeyToAddress(key.PublicKey)
		genesis = &core.Genesis{
			Config: params.TestChainConfig,
			Alloc:  core.GenesisAlloc{address: {Balance: big.NewInt(1000000000000000000)}},
		}
		signer = types.LatestSigner(genesis.Config)
	)

	// Generate chain.
	db, blocks, _ := core.GenerateChainWithGenesis(genesis, ethash.NewFaker(), int(count), func(i int, g *core.BlockGen) {
		if i == 0 {
			return
		}
		tx, err := types.SignNewTx(key, signer, &types.DynamicFeeTx{
			ChainID:    genesis.Config.ChainID,
			Nonce:      uint64(i - 1),
			GasTipCap:  common.Big0,
			GasFeeCap:  g.PrevBlock(0).BaseFee(),
			Gas:        50000,
			To:         &common.Address{0xaa},
			Value:      big.NewInt(int64(i)),
			Data:       nil,
			AccessList: nil,
		})
		if err != nil {
			t.Fatalf("error creating tx: %v", err)
		}
		g.AddTx(tx)
	})

	// Initialize BlockChain.
	chain, err := core.NewBlockChain(db, nil, genesis, nil, ethash.NewFaker(), vm.Config{}, nil, nil)
	if err != nil {
		t.Fatalf("unable to initialize chain: %v", err)
	}
	if _, err := chain.InsertChain(blocks); err != nil {
		t.Fatalf("error insterting chain: %v", err)
	}

	// Make temp directory for era files.
	dir, err := os.MkdirTemp("", "history-export-test")
	if err != nil {
		t.Fatalf("error creating temp test directory: %v", err)
	}
	defer os.RemoveAll(dir)

	// Export history to temp directory.
	if err := ExportHistory(chain, dir, 0, count, step); err != nil {
		t.Fatalf("error exporting history: %v", err)
	}

	// Verify each Era.
	for i := 0; i < int(count/step); i++ {
		f, err := os.Open(path.Join(dir, fmt.Sprintf("mainnet-%05d.era", i)))
		if err != nil {
			t.Fatalf("error opening era file: %v", err)
		}
		r := era.NewReader(f)
		for j := 0; ; j += 1 {
			b, r, err := r.Read()
			if err == io.EOF {
				break
			} else if err != nil {
				t.Fatalf("error reading era file %d: %v", i, err)
			}
			var (
				num  = i*int(step) + j
				want = chain.GetBlockByNumber(uint64(num))
			)
			if want, got := uint64(num), b.NumberU64(); want != got {
				t.Fatalf("blocks out of order: want %d, got %d", want, got)
			}
			if want.Hash() != b.Hash() {
				t.Fatalf("block hash mistmatch %d: want %s, got %s", i+j, want.Hash().Hex(), b.Hash().Hex())
			}
			if got := types.DeriveSha(r, trie.NewStackTrie(nil)); got != want.ReceiptHash() {
				t.Fatalf("receipt root %d mismatch: want %s, got %s", i+j, want.ReceiptHash(), got)
			}
		}
	}
}
