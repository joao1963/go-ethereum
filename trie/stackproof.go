package trie

import (
	"errors"
	"fmt"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/rlp"
)

// nodeToStNode converts from `node` to `*stNode`.
func nodeToStNode(n node, key []byte) *stNode {
	st := new(stNode)
	switch n := n.(type) {
	case *shortNode:
		st.nodeType = extNode
		st.key = append([]byte{}, n.Key...)
	case *fullNode:
		st.nodeType = branchNode
		idx := int(key[0])
		for i := 0; i < idx; i++ {
			sibling := n.Children[i]
			if sibling == nil {
				continue
			}
			siblingNode := new(stNode)
			siblingNode.nodeType = hashedNode

			if hash, ok := sibling.(hashNode); ok {
				siblingNode.val = []byte(hash)
			} else {
				// This happens is the sibling is small enough (<32B) to be inlined,
				// in which case the rlp-encoded node is embedded instead of the hash
				short := sibling.(*shortNode)
				short.Key = hexToCompact(short.Key)
				siblingNode.val = nodeToBytes(short)
			}
			st.children[i] = siblingNode
		}
	default:
		panic(fmt.Sprintf("%T", n))
	}
	return st
}

// stNodeToNode converts from `*stNode` to `node`.
func stNodeToNode(st *stNode) node {
	switch st.nodeType {
	case extNode: // a shortnode
		n := &shortNode{flags: newFlag()}
		n.Key = common.CopyBytes(st.key)
		n.Val = stNodeToNode(st.children[0])
		return n
	case branchNode: // a fullnode
		n := &fullNode{flags: newFlag()}
		for i, child := range st.children {
			if child != nil {
				n.Children[i] = stNodeToNode(child)
			}
		}
		return n
	case hashedNode: // an unresolved/hashed node
		if len(st.val) == 32 {
			n := make(hashNode, 32)
			copy(n, st.val)
			return n
		}
		// This is a shortnode, embedded inside the parent.
		// The stacktrie represents this case by rlp-encoding the node into
		// a hashnode, whereas the regular trie represents it as a regular
		// node within another node.
		// Therefore, we need to unmarshal the RLP back into a shortnode containing
		// the value.
		var dec struct {
			K []byte
			V []byte
		}
		rlp.DecodeBytes(st.val, &dec)
		return &shortNode{
			Key:   compactToHex(dec.K),
			Val:   valueNode(dec.V),
			flags: newFlag(),
		}
	case leafNode: // a valuenode
		vn := make(valueNode, len(st.val))
		copy(vn, st.val)
		n := &shortNode{flags: newFlag(), Key: common.CopyBytes(st.key), Val: vn}
		n.Key = append(n.Key, 16) // Add terminator
		return n
	}

	panic(fmt.Sprintf("unexpected type: %v", st.nodeType))
}

func resolveFromProof(proofDb ethdb.KeyValueReader, hash common.Hash) (node, error) {
	data, _ := proofDb.Get(hash[:])
	if data == nil {
		return nil, fmt.Errorf("proof node (hash %064x) missing", hash)
	}
	n, err := decodeNode(data[:], data)
	if err != nil {
		return nil, fmt.Errorf("bad proof node: %v", err)
	}
	return n, err
}

// newStackTrieFromProof creates a new stacktrie, and initialises it from the given
// proof. It does so by starting at the given root, traverses along the given
// key, and, one by one, converts the nodes into stacktrie elements.
//
// OBS: The resulting stacktrie instance is not guaranteed to be structurally
// identical to a stacktrie which is initialized from scratch by feeding the
// corresponding elements!
// A proof-initialized (PI) stack-trie has some implicit prescient knowledge! Therefore,
// a PI can have already expanded a shortnode into shortnode+fullnode, which a non-PI
// will do only later.
//
// However, the two guarantees that PI gives are:
// - Identical hash,
// - Identical commit-sequence of nodes.
//
// OBS 2: The element in proof should _not_ be added again during value-filling.
// OBS 3: Proofs-of-abscence have not been fully tested. TODO @holiman
func newStackTrieFromProof(rootHash common.Hash, key []byte, proofDb ethdb.KeyValueReader, writeFn NodeWriteFunc) (*StackTrie, error) {
	var (
		err               error
		child, parent     node
		stChild, stParent *stNode
		keyrest           []byte
		stack             = NewStackTrie(writeFn)
	)
	key = keybytesToHex(key)
	// First we need to resolve the root node from the proof.
	if parent, err = resolveFromProof(proofDb, rootHash); err != nil {
		return nil, err
	}
	stParent = nodeToStNode(parent, key)
	stack.root = stParent
	// Now we pursue the given key downwards, and populate the stacktrie too
	for {
		keyrest, child = get(parent, key, false)
		switch cld := child.(type) {
		case nil:
			return nil, errors.New("no node at given path")
		case hashNode:
			child, err = resolveFromProof(proofDb, common.BytesToHash(cld))
			if err != nil {
				return nil, err
			}
		case valueNode:
			// The value node goes right into the child
			stParent.val = common.CopyBytes(cld)
			stParent.nodeType = leafNode
			// remove the terminator
			stParent.key = stParent.key[:len(stParent.key)-1]
			return stack, nil
		case *shortNode:
			// In the case of small leaves, we might end up here with a fullnode
			// whose child is an embedded *shortNode.
		default:
			// we don't expect fullnodes
			panic(fmt.Sprintf("got %T", cld))
		}
		stChild = nodeToStNode(child, keyrest) // convert to stacktrie equivalent
		// Link the parent and child.
		switch pnode := parent.(type) {
		case *shortNode:
			stParent.children[0] = stChild
		case *fullNode:
			stParent.children[key[0]] = stChild
		default:
			panic(fmt.Sprintf("%T: invalid node: %v", pnode, pnode))
		}
		key = keyrest
		parent = child
		stParent = stChild
	}
}

// toRegularTrie converts stack to a regular *trie.Trie.
func (stack *StackTrie) toRegularTrie() *Trie {
	tr := NewEmpty(nil)
	tr.root = stNodeToNode(stack.root)
	tr.owner = stack.owner
	return tr
}

func (st *stNode) dumpTrie(lvl int) {
	var indent []byte
	for i := 0; i < lvl; i++ {
		indent = append(indent, ' ')
	}
	switch st.nodeType {
	case branchNode:
		fmt.Printf("\n%s FN (key='%#x')", string(indent), st.key)

		for i := 0; i < 16; i++ {
			if st.children[i] == nil {
				continue
			}
			fmt.Printf("\n%s %#x. ", string(indent), i)
			st.children[i].dumpTrie(lvl + 1)
		}
		fmt.Println("")
	case extNode:
		fmt.Printf("%s: sn('%#x')", string(indent), st.key)
		st.children[0].dumpTrie(lvl + 1)
	case leafNode:
		fmt.Printf("%s: leaf('%#x'): %x ", string(indent), st.key, st.val)
	case hashedNode:
		fmt.Printf("hash: %#x %x", st.val, st.key)
	default:
		fmt.Printf("Foo: %d ? ", st.nodeType)
	}
}
