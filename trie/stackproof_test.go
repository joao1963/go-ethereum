package trie

import (
	"fmt"
	"sort"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethdb/memorydb"
)

type keyValue struct {
	k []byte
	v []byte
}

func TestSTProof(t *testing.T) {

	pair := func(k, v string) *kv { return &kv{k: common.FromHex(k), v: common.FromHex(v)} }

	entries := entrySlice{
		// These should form a lefthand side node
		pair("0x00000000000000000000000000000001", "111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111"),
		pair("0x00000000000000000000000000000002", "222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222"),
		pair("0x00000000000000000000000000000003", "333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333"),
		pair("0x00000000000000000000000000000004", "444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444"),
		// These should for a fullnode in the middle
		pair("0x61111111111111111111100000000000", "555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555"),
		pair("0x61111111111111111111100000000001", "666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666"),
		pair("0x61111111111111111111100000000002", "777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777"),

		pair("0x61111111111111111111111111111111", "888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888"),
		pair("0x61111111111111111111111111111112", "999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999"),

		pair("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
	}
	sort.Sort(entries)
	refTrie, _ := New(common.Hash{}, NewDatabase(memorydb.New()))
	for _, kv := range entries {
		refTrie.TryUpdate(kv.k, kv.v)
	}
	//testStackTrieLeftsideProof(t, entries, refTrie, 7)
	//testStackTrieLeftsideProof(t, entries, refTrie, 6)
	//testStackTrieLeftsideProof(t, entries, refTrie, 5)
	//testStackTrieLeftsideProof(t, entries, refTrie, 4)
	//testStackTrieLeftsideProof(t, entries, refTrie, 3)
	//testStackTrieLeftsideProof(t, entries, refTrie, 2)
	//testStackTrieLeftsideProof(t, entries, refTrie, 1)
	//testStackTrieLeftsideProof(t, entries, refTrie, 0)

	testStackTrieRightsideProof(t, entries, refTrie, 2)

}

func TestSTProofRandom(t *testing.T) {

	trie, vals := randomTrie(8192)
	var entries entrySlice
	for _, kv := range vals {
		entries = append(entries, kv)
	}
	sort.Sort(entries)

	refTrie, _ := New(common.Hash{}, NewDatabase(memorydb.New()))
	for _, kv := range entries {
		refTrie.TryUpdate(kv.k, kv.v)
	}
	testStackTrieRightsideProof(t, entries, trie, 7)
	//testStackTrieLeftsideProof(t, entries, trie, 7)
	//testStackTrieLeftsideProof(t, entries, refTrie, 6)
	//testStackTrieLeftsideProof(t, entries, refTrie, 5)
	//testStackTrieLeftsideProof(t, entries, refTrie, 4)
	//testStackTrieLeftsideProof(t, entries, refTrie, 3)
	//testStackTrieLeftsideProof(t, entries, refTrie, 2)
	//testStackTrieLeftsideProof(t, entries, refTrie, 1)
}

func prepareStackTrie(key []byte, proof []interface{}) (*StackTrie, error) {
	path := keybytesToHex(key)
	pathIndex := len(path) - 1
	makeFNParent := func(fn fullN, child *StackTrie) *StackTrie {
		newNode := &StackTrie{
			nodeType:  branchNode,
			key:       common.CopyBytes(path[:pathIndex]),
			keyOffset: pathIndex,
		}
		// Add the hashed left-hand siblings
		for k, v := range fn.siblings {
			newNode.children[k] = &StackTrie{
				val:      common.CopyBytes(v.([]byte)),
				nodeType: hashedNode,
			}
		}
		newNode.children[path[pathIndex]] = child
		pathIndex--
		return newNode
	}
	makeSNParent := func(sn shortN, child *StackTrie) *StackTrie {
		pathIndex -= len(sn.ext)
		elem := &StackTrie{
			key:       common.CopyBytes(sn.ext),
			keyOffset: pathIndex + 1,
		}
		if child != nil {
			elem.nodeType = extNode
			elem.children[0] = child
			return elem
		}
		// If we're not adding a child node here, then this is the leaf
		elem.nodeType = leafNode
		elem.val = common.CopyBytes(sn.val)
		// remove the terminator
		elem.key = elem.key[:len(elem.key)-1]
		return elem
	}
	var st *StackTrie
	// Go bottom up, so reverse the proof list
	for i := len(proof) - 1; i >= 0; i-- {
		v := proof[i]
		switch vv := v.(type) {
		case fullN:
			st = makeFNParent(vv, st)
		case shortN:
			st = makeSNParent(vv, st)
		}
	}
	return st, nil
}

func postfixStackTrie(st *StackTrie, key []byte, proof []interface{}) error {
	// TODO fix this one up properly
	path := keybytesToHex(key)
	pathIndex := len(path) - 1
	makeFNParent := func(fn fullN, child *StackTrie) *StackTrie {
		newNode := &StackTrie{
			nodeType:  branchNode,
			key:       common.CopyBytes(path[:pathIndex]),
			keyOffset: pathIndex,
		}
		// Add the hashed left-hand siblings
		for k, v := range fn.siblings {
			newNode.children[k] = &StackTrie{
				val:      common.CopyBytes(v.([]byte)),
				nodeType: hashedNode,
			}
		}
		newNode.children[path[pathIndex]] = child
		pathIndex--
		return newNode
	}
	makeSNParent := func(sn shortN, child *StackTrie) *StackTrie {
		pathIndex -= len(sn.ext)
		elem := &StackTrie{
			key:       common.CopyBytes(sn.ext),
			keyOffset: pathIndex + 1,
		}
		if child != nil {
			elem.nodeType = extNode
			elem.children[0] = child
			return elem
		}
		// If we're not adding a child node here, then this is the leaf
		elem.nodeType = leafNode
		elem.val = common.CopyBytes(sn.val)
		// remove the terminator
		elem.key = elem.key[:len(elem.key)-1]
		return elem
	}
	// Go bottom up, so reverse the proof list
	var paths []string
	cur := ""
	index := 0
	for i := 0; i < len(proof)-1; i++ {

		v := proof[i]

		paths = append(paths, cur)
		switch vv := v.(type) {
		case fullN:
			index++
			path := string([]byte{key[index]})
			paths = append(paths, path)
			cur = path
			fmt.Printf("Adding fn at path %x\n", path)
		case shortN:
			path := string(key[index : index+len(vv.ext)/2])
			index += len(vv.ext) / 2
			cur = path
			fmt.Printf("Adding sn at path %x\n", path)
			paths = append(paths, path)
		}
	}
	fmt.Printf("Paths: %x\n", paths)

	for i := len(proof) - 1; i >= 0; i-- {
		v := proof[i]
		switch vv := v.(type) {
		case fullN:

			fmt.Printf("Fullnode\n")
			if false {
				st = makeFNParent(vv, st)

			}
			for ii, c := range vv.siblings {
				if c != nil {
					fmt.Printf("At %d: %x\n", ii, c)
				}
			}
			continue
		case shortN:
			fmt.Printf("Shortnode %x %x\n", vv.ext, vv.val)
			st.insertHash(vv.ext, vv.val)
			if false {
				st = makeSNParent(vv, st)

			}

		}
	}
	return nil
}

func testStackTrieLeftsideProof(t *testing.T, kvs entrySlice, refTrie *Trie, index int) {
	// Prove elem
	prefix, err := refTrie.ProveWithPathsLeftSide(kvs[index].k)
	if err != nil {
		t.Fatal(err)
	}

	st, err := prepareStackTrie(kvs[index].k, prefix)
	if err != nil {
		t.Fatal(err)
	}
	//st.dumpTrie(0)
	for _, kv := range kvs[index+1:] {
		st.TryUpdate(kv.k, common.CopyBytes(kv.v))
	}
	// 0x307f372f659f8d9424f88904d4489f932ba77b73eade773235584d8348801253
	t.Logf("st root: %#x", st.Hash())
	if want, have := refTrie.Hash(), st.Hash(); have != want {
		t.Fatalf("Proving element %d, have %#x, want %#x", index, have, want)
	}
}

func testStackTrieRightsideProof(t *testing.T, kvs entrySlice, refTrie *Trie, index int) {
	st := NewStackTrie(nil)
	for _, kv := range kvs[:index] {
		st.TryUpdate(kv.k, common.CopyBytes(kv.v))
	}
	// Prove elem
	suffix, err := refTrie.ProveWithPathsRightSide(kvs[index].k)
	if err != nil {
		t.Fatal(err)
	}

	if err := postfixStackTrie(st, kvs[index].k, suffix); err != nil {
		t.Fatal(err)
	}
	//st.dumpTrie(0)
	// 0x307f372f659f8d9424f88904d4489f932ba77b73eade773235584d8348801253
	t.Logf("st root: %#x", st.Hash())
	if want, have := refTrie.Hash(), st.Hash(); have != want {
		t.Fatalf("Proving element %d, have %#x, want %#x", index, have, want)
	}
}

func BenchmarkRangeVerification10(b *testing.B)   { benchmarkVerifyStackRangeProof(b, 10) }
func BenchmarkRangeVerification100(b *testing.B)  { benchmarkVerifyStackRangeProof(b, 100) }
func BenchmarkRangeVerification1000(b *testing.B) { benchmarkVerifyStackRangeProof(b, 1000) }
func BenchmarkRangeVerification5000(b *testing.B) { benchmarkVerifyStackRangeProof(b, 5000) }

func benchmarkVerifyStackRangeProof(b *testing.B, size int) {
	trie, vals := randomTrie(8192)
	var entries entrySlice
	for _, kv := range vals {
		entries = append(entries, kv)
	}
	sort.Sort(entries)
	start := len(entries) - size
	//start := 2
	end := len(entries) - 1
	//end := start + size
	proof := memorydb.New()
	if err := trie.Prove(entries[start].k, 0, proof); err != nil {
		b.Fatalf("Failed to prove the first node %v", err)
	}
	if err := trie.Prove(entries[end-1].k, 0, proof); err != nil {
		b.Fatalf("Failed to prove the last node %v", err)
	}
	var keys [][]byte
	var values [][]byte
	for i := start; i < end; i++ {
		keys = append(keys, entries[i].k)
		values = append(values, entries[i].v)
	}

	b.Run("rangeprover", func(b *testing.B) {
		b.ResetTimer()
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			_, err := VerifyRangeProof(trie.Hash(), keys[0], keys[len(keys)-1], keys, values, proof)
			if err != nil {
				b.Fatalf("Case %d(%d->%d) expect no error, got %v", i, start, end-1, err)
			}
		}
	})

	b.Run("stackbased", func(b *testing.B) {
		key := common.CopyBytes(keys[0])
		plist, err := trie.ProveWithPathsLeftSide(key)
		if err != nil {
			b.Fatal(err)
		}
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			st, err := prepareStackTrie(key, plist)
			if err != nil {
				b.Fatal(err)
			}
			for _, kv := range entries[start+1:] {
				st.TryUpdate(kv.k, common.CopyBytes(kv.v))
			}
			if st.Hash() != trie.Hash() {
				b.Fatalf("Case %d(%d->%d) expect no error, got %v", i, start, end-1, st.Hash())
			}
		}
	})
}

func dumpTrie(n node, lvl int) {
	var indent []byte
	for i := 0; i < lvl; i++ {
		indent = append(indent, ' ')
	}
	switch nn := n.(type) {
	case nil:
		fmt.Printf("<nil>")
	case *fullNode:
		for i := 0; i < 16; i++ {
			if nn.Children[i] == nil {
				continue
			}
			fmt.Printf("\n%s %#x. ", string(indent), i)
			dumpTrie(nn.Children[i], lvl+1)
		}
		fmt.Println("")
	case *shortNode:
		fmt.Printf("%s: sn(%#x)", string(indent), nn.Key)
		dumpTrie(nn.Val, lvl+1)
	case valueNode:
		fmt.Printf(" %x", string(nn))
	default:
		fmt.Printf("%T", nn)
	}
}
