package trie

import (
	"fmt"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

// Hash returns the root hash of the trie. It does not write to the
// database and can be used even if the trie doesn't have one.
func (it *IncTrie) xHash() common.Hash {
	hashP := it.hashRec(it.root)
	if len(hashP) < 32 {
		return crypto.Keccak256Hash(hashP)
	}
	return common.BytesToHash(hashP)
	//return t.Hash()
}
func (it *IncTrie) hashRec(n node) []byte {
	// The switch below sets this to the RLP-encoding of this node.
	var encodedNode []byte
	//fmt.Printf("->hashRec(%T)\n", n)
	//defer fmt.Printf("<-hashRec(%T)\n", n)
	switch n := n.(type) {
	case hashNode:
		return n
	case valueNode:
		return n
	case nil:
		//return nilValueNode
		return emptyRoot.Bytes()
	case *fullNode:
		var nodes rawFullNode
		for i := 0; i < 16; i++ {
			child := n.Children[i]
			if child == nil {
				nodes[i] = nilValueNode
				continue
			}
			hn := it.hashRec(child)
			//child.hashRec(hasher)
			if len(hn) < 32 {
				nodes[i] = rawNode(hn)
			} else {
				nodes[i] = hashNode(hn)
			}

			// Release child back to pool.
			n.Children[i] = nil
			//st.children[i] = nil
			//returnToPool(child)
		}
		nodes.encode(it.h.encbuf)
		encodedNode = it.h.encodedBytes()

	case *shortNode:
		//sz := hexToCompactInPlace(n.Key)
		rn := rawShortNode{Key: hexToCompact(n.Key)}
		_, childIsFn := n.Val.(*fullNode)
		hn := it.hashRec(n.Val)
		if len(hn) < 32 {
			if childIsFn {
				rn.Val = rawNode(hn)
			} else {
				rn.Val = valueNode(hn)
			}
		} else {
			rn.Val = hashNode(hn)
		}
		rn.encode(it.h.encbuf)
		encodedNode = it.h.encodedBytes()

		// Release child back to pool.
		//returnToPool(st.children[0])
		n.Val = nil
	default:
		panic(fmt.Sprintf("invalid node type %T", n))
	}

	//st.nodeType = hashedNode
	//st.key = st.key[:0]
	if len(encodedNode) < 32 {
		return common.CopyBytes(encodedNode)
		//st.val = common.CopyBytes(encodedNode)
		//return
	}

	// Write the hash to the 'val'. We allocate a new val here to not mutate
	// input values
	return it.h.hashData(encodedNode)
}
