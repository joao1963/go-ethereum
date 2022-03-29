package trie

import (
	"bytes"
	"fmt"
	"github.com/ethereum/go-ethereum/common"
)

// IncTrie is a Merkle Patricia Trie. The IncTrie supports ordered insertion only,
// and does _not_ resolve nodes from a database.
// - Ordered insertion only,
// - Does not support delete.
// It incrementally hashes parts of the tree to the 'left', as new values are inserted.
// The zero value is an empty trie.
//
// IncTrie is not safe for concurrent use.
type IncTrie struct {
	root node
	h    *hasher
}

func NewIncTrie() *IncTrie {
	return &IncTrie{
		h: newHasher(false),
	}
}

func (t *IncTrie) Done() {
	returnHasherToPool(t.h)
	t.h = nil
}

func (t *IncTrie) TryUpdate(key, value []byte) error {
	if len(value) == 0 {
		panic("deletion not supported")
	}
	k := keybytesToHex(key)
	_, n, err := t.insert(t.root, nil, k, valueNode(value))
	if err != nil {
		return err
	}
	t.root = n

	return nil
}

func (t *IncTrie) newFlag() nodeFlag {
	return nodeFlag{dirty: true}
}

func (t *IncTrie) insert(n node, prefix, key []byte, value node) (bool, node, error) {
	if len(key) == 0 {
		if v, ok := n.(valueNode); ok {
			return !bytes.Equal(v, value.(valueNode)), value, nil
		}
		return true, value, nil
	}
	switch n := n.(type) {
	case *shortNode:
		matchlen := prefixLen(key, n.Key)
		// If the whole key matches, keep this short node as is
		// and only update the value.
		if matchlen == len(n.Key) {
			dirty, nn, err := t.insert(n.Val, append(prefix, key[:matchlen]...), key[matchlen:], value)
			if !dirty || err != nil {
				return false, n, err
			}
			n.Val = nn
			n.flags.hash = nil
			n.flags.dirty = true
			return true, n, nil
			//return true, &shortNode{n.Key, nn, t.newFlag()}, nil
		}
		// Otherwise branch out at the index where they differ.
		branch := &fullNode{flags: t.newFlag()}
		var err error

		// We can hash the left side immediately -- but fails a test if we do so (?)
		//if n.Key[matchlen] > key[matchlen] {
		//	panic("foo")
		//}
		//_, previousNode, err := t.insert(nil, append(prefix, n.Key[:matchlen+1]...), n.Key[matchlen+1:], n.Val)
		//if err != nil {
		//	return false, nil, err
		//}
		//hn, _ := t.h.hash(previousNode, false)
		//branch.Children[n.Key[matchlen]] = hn

		_, branch.Children[n.Key[matchlen]], err = t.insert(nil, append(prefix, n.Key[:matchlen+1]...), n.Key[matchlen+1:], n.Val)
		if err != nil {
			return false, nil, err
		}
		_, branch.Children[key[matchlen]], err = t.insert(nil, append(prefix, key[:matchlen+1]...), key[matchlen+1:], value)
		if err != nil {
			return false, nil, err
		}
		// Replace this shortNode with the branch if it occurs at index 0.
		if matchlen == 0 {
			return true, branch, nil
		}
		// Otherwise, replace it with a short node leading up to the branch.
		//return true, &shortNode{key[:matchlen], branch, t.newFlag()}, nil
		n.Key = n.Key[:matchlen]
		n.Val = branch
		n.flags.hash = nil
		n.flags.dirty = true
		return true, n, nil
		//return true, &shortNode{key[:matchlen], branch, t.newFlag()}, nil

	case *fullNode:
		// Unresolve elder siblings
		idx := int(key[0])
		for i := idx - 1; i >= 0; i-- {
			child := n.Children[i]
			if child != nil {
				hn, _ := t.h.hash(child, true)
				n.Children[i] = hn
				break
			}
		}
		dirty, nn, err := t.insert(n.Children[key[0]], append(prefix, key[0]), key[1:], value)
		if !dirty || err != nil {
			return false, n, err
		}
		//n = n.copy()
		//n.flags = t.newFlag()
		n.flags.hash = nil
		n.flags.dirty = true
		n.Children[key[0]] = nn
		return true, n, nil

	case nil:
		return true, &shortNode{key, value, t.newFlag()}, nil

	case hashNode:
		panic("trying to insert into existing hash")
	default:
		panic(fmt.Sprintf("%T: invalid node: %v", n, n))
	}
}

// Hash returns the root hash of the trie. It does not write to the
// database and can be used even if the trie doesn't have one.
func (it *IncTrie) trieHash() common.Hash {
	t := Trie{
		root:     it.root,
		unhashed: 1,
	}
	return t.Hash()
}
func (t *IncTrie) Hash() common.Hash {
	return t.trieHash()
}

func (t *IncTrie) customHash() common.Hash {
	hash, cached, _ := t.hashRoot()
	t.root = cached
	return common.BytesToHash(hash.(hashNode))
}

// hashRoot calculates the root hash of the given trie
func (t *IncTrie) hashRoot() (node, node, error) {
	if t.root == nil {
		return hashNode(emptyRoot.Bytes()), nil, nil
	}
	hashed, cached := t.h.hash(t.root, true)
	return hashed, cached, nil
}
