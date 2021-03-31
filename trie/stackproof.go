package trie

import (
	"bytes"
	"fmt"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/log"
)

type pathProof struct {
	path  []byte
	proof []byte
}
type shortN struct {
	ext []byte
	val []byte
}
type fullN struct {
	siblings map[int]interface{}
}

// ProveWithPathsLeftSide constructs a merkle proof for key. The result contains all encoded nodes
// on the path to the value at key, and their paths. The value itself is also included in the last
// node and can be retrieved by verifying the proof.
//
// If the trie does not contain a value for key, the returned proof contains all
// nodes of the longest existing prefix of the key (at least the root node), ending
// with the node that proves the absence of the key.
func (t *Trie) ProveWithPathsLeftSide(key []byte) ([]interface{}, error) {
	// Collect all nodes on the path to key.
	key = keybytesToHex(key)
	var proofs []interface{}
	tn := t.root
	hasher := newHasher(false)
	defer returnHasherToPool(hasher)
	for len(key) > 0 && tn != nil {
		switch n := tn.(type) {
		case *fullNode:
			// Collect lower-sibling hashes
			collapsed, _ := hasher.hashFullNodeChildren(n)
			x := fullN{
				siblings: make(map[int]interface{}),
			}
			for i := byte(0); i < key[0]; i++ {
				sibling := n.Children[i]
				if sibling == nil {
					continue
				}
				enc := collapsed.Children[i].(hashNode)
				x.siblings[int(i)] = []byte(enc)
			}
			proofs = append(proofs, x)
			tn = n.Children[key[0]]
			key = key[1:]
		case *shortNode:
			if len(key) < len(n.Key) || !bytes.Equal(n.Key, key[:len(n.Key)]) {
				// The trie doesn't contain the key.
				tn = nil
			} else {
				tn = n.Val
				x := shortN{
					ext: common.CopyBytes(n.Key),
				}
				if len(key) == len(n.Key) {
					x.val = common.CopyBytes(n.Val.(valueNode))
				}
				proofs = append(proofs, x)
				key = key[len(n.Key):]
			}
		case hashNode:
			var err error
			tn, err = t.resolveHash(n, nil)
			if err != nil {
				log.Error(fmt.Sprintf("Unhandled trie error: %v", err))
				return nil, err
			}
		default:
			panic(fmt.Sprintf("%T: invalid node: %v", tn, tn))
		}
	}
	return proofs, nil
}

func (t *Trie) ProveWithPathsRightSide(key []byte) ([]interface{}, error) {
	// Collect all nodes on the path to key.
	key = keybytesToHex(key)
	var proofs []interface{}
	tn := t.root
	hasher := newHasher(false)
	defer returnHasherToPool(hasher)
	for len(key) > 0 && tn != nil {
		switch n := tn.(type) {
		case *fullNode:
			// Collect higher-sibling hashes
			collapsed, _ := hasher.hashFullNodeChildren(n)
			x := fullN{
				siblings: make(map[int]interface{}),
			}
			for i := key[0]; i < 17; i++ {
				sibling := n.Children[i]
				if sibling == nil {
					continue
				}
				enc := collapsed.Children[i].(hashNode)
				x.siblings[int(i)] = []byte(enc)
			}
			proofs = append(proofs, x)
			tn = n.Children[key[0]]
			key = key[1:]
		case *shortNode:
			if len(key) < len(n.Key) || !bytes.Equal(n.Key, key[:len(n.Key)]) {
				// The trie doesn't contain the key.
				tn = nil
			} else {
				tn = n.Val
				x := shortN{
					ext: common.CopyBytes(n.Key),
				}
				if len(key) == len(n.Key) {
					x.val = common.CopyBytes(n.Val.(valueNode))
				}
				proofs = append(proofs, x)
				key = key[len(n.Key):]
			}
		case hashNode:
			var err error
			tn, err = t.resolveHash(n, nil)
			if err != nil {
				log.Error(fmt.Sprintf("Unhandled trie error: %v", err))
				return nil, err
			}
		default:
			panic(fmt.Sprintf("%T: invalid node: %v", tn, tn))
		}
	}
	return proofs, nil
}
