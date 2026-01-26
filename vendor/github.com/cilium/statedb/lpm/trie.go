// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package lpm

import (
	"bytes"
	"fmt"
	"math/bits"
	"strings"

	"github.com/cilium/statedb/index"
)

type PrefixLen = uint16

func New[T any]() Trie[T] {
	return Trie[T]{
		root: nil,
	}
}

type Trie[T any] struct {
	root      *lpmNode[T]
	size      int
	prevTxnID uint64 // ID of the transaction that produced this
}

func (l *Trie[T]) Txn() *Txn[T] {
	txnID := l.prevTxnID + 1
	return &Txn[T]{
		root:  l.root,
		size:  l.size,
		txnID: txnID,
	}
}

func (l *Trie[T]) Len() int {
	return l.size
}

func (l *Trie[T]) Print() {
	if l.root == nil {
		fmt.Printf("<empty>\n")
		return
	}
	var printNode func(*lpmNode[T], int)
	printNode = func(ln *lpmNode[T], indent int) {
		img := ""
		if ln.imaginary {
			img = "*"
		}
		fmt.Printf("%s%s%s -> %v\n", strings.Repeat(" ", indent), showKey(ln.key), img, ln.value)
		if ln.children[0] != nil {
			printNode(ln.children[0], indent+2)
		}
		if ln.children[1] != nil {
			printNode(ln.children[1], indent+2)
		}
	}
	printNode(l.root, 0)
}

func (l *Trie[T]) All() *Iterator[T] {
	if l.root == nil {
		return nil
	}
	return &Iterator[T]{start: l.root}
}

func (l *Trie[T]) Prefix(key index.Key) *Iterator[T] {
	txn := Txn[T]{root: l.root, size: l.size}
	return txn.Prefix(key)
}

func (l *Trie[T]) LowerBound(key index.Key) *Iterator[T] {
	txn := Txn[T]{root: l.root, size: l.size}
	return txn.LowerBound(key)
}

func (l *Trie[T]) Lookup(key index.Key) (value T, found bool) {
	return lpmLookup(l.root, key)
}

func (l *Trie[T]) LookupExact(key index.Key) (value T, found bool) {
	return lpmLookupExact(l.root, key)
}

type lpmNode[T any] struct {
	children [2]*lpmNode[T]

	// txnID is the ID of the transaction that last cloned this node. Used to detect
	// if it can be mutated in-place.
	txnID uint64

	value T
	key   index.Key

	// imaginary is a node that holds no value but has children that share the
	// common prefix.
	imaginary bool
}

func (n *lpmNode[T]) prefixLen() PrefixLen {
	_, len := DecodeLPMKey(n.key)
	return len
}

type Txn[T any] struct {
	// root is the current root of the trie
	root *lpmNode[T]

	// deletedParentsCache is the previously used chain of parents used during deletion.
	// We cache it here so we don't need to allocate a fresh one for each deletion.
	deletedParentsCache []lpmDeleteParent[T]

	// size is the number of nodes currently in [root]
	size int

	// txnID is a monotonically increasing integer that is assigned when the Txn
	// is created from a [Trie] and is used to detect whether a node has been
	// cloned during this transaction or not to allow mutating it in place.
	// txnID is also incremented when returning an iterator in order to not
	// mutate the tree used by the iterator as that would mess up iteration.
	txnID uint64
}

type lpmDeleteParent[T any] struct {
	node  *lpmNode[T]
	index int
}

// Clear the transaction for reuse.
func (txn *Txn[T]) Clear() {
	txn.size = 0
	txn.root = nil
	txn.txnID = 0
	clear(txn.deletedParentsCache)
}

func (txn *Txn[T]) Reuse(trie Trie[T]) *Txn[T] {
	txn.size = trie.size
	txn.root = trie.root
	txn.txnID = trie.prevTxnID + 1
	return txn
}

func (txn *Txn[T]) clone(n *lpmNode[T]) *lpmNode[T] {
	if n == nil {
		return nil
	}

	if n.txnID == txn.txnID {
		return n
	}

	n2 := *n
	n = &n2
	n.txnID = txn.txnID
	return n
}

func (txn *Txn[T]) Insert(key index.Key, value T) error {
	if runValidation {
		defer func() {
			validateTrieRoot(txn.root, txn.size, txn.txnID)
		}()
	}

	data, prefixLen := DecodeLPMKey(key)
	newNode := &lpmNode[T]{
		children:  [2]*lpmNode[T]{},
		key:       key,
		value:     value,
		imaginary: false,
		txnID:     txn.txnID,
	}

	txn.root = txn.clone(txn.root)
	nodep := &txn.root
	node := *nodep

	// Find the closest node to insert the value into.
	// [matchLen] is the number of common bits between [node.key] and
	// our insertion [key].
	var matchLen PrefixLen
	for node != nil {
		matchLen = longestMatch(matchLen, node, data, prefixLen)
		nodePrefixLen := node.prefixLen()

		// Did we match all the bits or just partially?
		if matchLen == prefixLen || matchLen != nodePrefixLen {
			break
		}

		// Node's prefix matched but there's more bits to look at,
		// recurse further.
		nodep = &node.children[getBitAt(data, nodePrefixLen)]
		*nodep = txn.clone(*nodep)
		node = *nodep
	}

	if node == nil {
		// Empty trie or a free children slot to insert into.
		*nodep = newNode
		txn.size++
		return nil
	}

	// Did we match all the bits in the [key]?
	if matchLen == prefixLen {
		if matchLen == node.prefixLen() {
			// Node with matching prefixing exists. Swap it with a new node
			// that has the new value. Only increment the size if we're swapping
			// a non-imaginary node with an old value.
			if node.imaginary {
				txn.size++
			}
			newNode.children = node.children
			*nodep = newNode
		} else {
			// Node with a shared prefix, but longer length exists.
			// Add it as the child of the new node.
			txn.size++
			index := getBitAt(node.key, matchLen)
			newNode.children[index] = node
			*nodep = newNode
		}
		return nil
	}

	// We found a [node] with which we matched fewer bits than are in the [key].
	// As they can't exist in the same location we'll need to fork the tree
	// with an imaginary node at the point where their prefixes diverge.
	txn.size++
	imaginary := &lpmNode[T]{
		key:       EncodeLPMKey(node.key, matchLen),
		imaginary: true,
		txnID:     txn.txnID,
	}
	bit := getBitAt(data, matchLen)
	imaginary.children[bit] = newNode
	imaginary.children[bit^1] = node
	*nodep = imaginary
	return nil
}

func (txn *Txn[T]) Len() int {
	return txn.size
}

func (txn *Txn[T]) Delete(key index.Key) (value T, found bool) {
	if runValidation {
		defer func() {
			validateTrieRoot(txn.root, txn.size, txn.txnID)
		}()
	}

	// parents tracks the nodes encountered on our way to the node containing
	// the value for [key].
	var parents []lpmDeleteParent[T]
	if txn.deletedParentsCache == nil {
		// No previous allocation. Start with a reasonably large capacity..
		parents = make([]lpmDeleteParent[T], 0, 32)
	} else {
		// Reuse the previous allocation.
		parents = txn.deletedParentsCache[:0]
	}
	// After we're done return the potentially larger slice for reuse.
	defer func() {
		txn.deletedParentsCache = parents[:0]
	}()

	data, prefixLen := DecodeLPMKey(key)
	var matchLen PrefixLen
	node := txn.root
	index := 0

	// Find the node containing the value we want to remove.
	// Collect the parent nodes on the path to the target.
	for node != nil {
		matchLen = longestMatch(matchLen, node, data, prefixLen)
		nodePrefixLen := node.prefixLen()

		// Exact prefix match?
		if matchLen == prefixLen && matchLen == nodePrefixLen {
			if node.imaginary {
				// Imaginary node, so there is no value.
				return
			}
			// Exact match on non-imaginery node. We found the node
			// to delete the value from.
			break
		}

		if matchLen < nodePrefixLen {
			// Mismatching prefix. The key doesn't exist in the tree.
			return
		}

		index = getBitAt(data, matchLen)
		parents = append(parents, lpmDeleteParent[T]{node, index})
		node = node.children[index]
	}
	if node == nil {
		return
	}

	txn.size--
	value = node.value

	// Turn the node imaginary to mark it for removal.
	node = txn.clone(node)
	var zero T
	node.value = zero
	node.imaginary = true

	// Reconstruct the parents, compressing the trie along the way.
	// [node] will be the new root at the end of this.
	for i := len(parents) - 1; i >= 0; i-- {
		oldParent := parents[i].node
		parent := txn.clone(oldParent)
		parents[i].node = parent
		index := parents[i].index
		if node.imaginary {
			switch {
			case node.children[0] == nil && node.children[1] == nil:
				// Node is empty and can be removed from the parent.
				node = nil
			case node.children[0] != nil && node.children[1] == nil:
				// Single child can be promoted regardless of side.
				node = node.children[0]
			case node.children[0] == nil && node.children[1] != nil:
				// Single child can be promoted regardless of side.
				node = node.children[1]
			}
		}
		parent.children[index] = node
		node = parent

		if oldParent.txnID == txn.txnID && parent.imaginary {
			if parent.children[0] != nil && parent.children[1] != nil {
				// The parent was already cloned and all pointers upwards from here
				// are already correct and we have 2 children so no need for compression.
				// Thus we can stop early.
				return value, true
			}
		}
	}

	// Drop imaginary root nodes that only have a single child.
	if node.imaginary {
		switch {
		case node.children[0] == nil && node.children[1] == nil:
			node = nil
		case node.children[0] != nil && node.children[1] == nil:
			node = node.children[0]
		case node.children[0] == nil && node.children[1] != nil:
			node = node.children[1]
		}
	}

	txn.root = node
	return value, true
}

func (txn *Txn[T]) Lookup(key index.Key) (value T, found bool) {
	return lpmLookup(txn.root, key)
}

func (txn *Txn[T]) LookupExact(key index.Key) (value T, found bool) {
	return lpmLookupExact(txn.root, key)
}

func (txn *Txn[T]) All() *Iterator[T] {
	if txn.root == nil {
		return nil
	}
	// Bump txnID to freeze the trie
	txn.txnID++
	return &Iterator[T]{start: txn.root}
}

func (txn *Txn[T]) Prefix(key index.Key) *Iterator[T] {
	if txn.root == nil {
		return nil
	}
	// Bump txnID to freeze the trie
	txn.txnID++

	node := txn.root
	data, prefixLen := DecodeLPMKey(key)

	var matchLen PrefixLen
	for node != nil {
		matchLen = longestMatch(matchLen, node, data, prefixLen)
		if matchLen == prefixLen || matchLen < node.prefixLen() {
			break
		}
		node = node.children[getBitAt(data, node.prefixLen())]
	}
	if node == nil {
		return nil
	}
	return &Iterator[T]{start: node}
}

func (txn *Txn[T]) LowerBound(key index.Key) *Iterator[T] {
	if txn.root == nil {
		return nil
	}
	// Bump the txnID to freeze the trie
	txn.txnID++

	data, prefixLen := DecodeLPMKey(key)
	node := txn.root
	stack := make([]*lpmNode[T], 0, 32)
	var matchLen PrefixLen
	for node != nil {
		matchLen = longestMatch(matchLen, node, data, prefixLen)
		if matchLen == prefixLen {
			stack = append(stack, node)
			break
		}
		if matchLen < node.prefixLen() {
			if bytes.Compare(node.key, data) >= 0 {
				stack = append(stack, node)
			}
			break
		}
		index := getBitAt(data, node.prefixLen())
		if index == 0 && node.children[1] != nil {
			// Add all the larger children to the stack.
			stack = append(stack, node.children[1])
		}
		node = node.children[index]
	}
	return &Iterator[T]{stack: stack}
}

func (txn *Txn[T]) Commit() Trie[T] {
	return Trie[T]{
		root:      txn.root,
		size:      txn.size,
		prevTxnID: txn.txnID,
	}
}

// longestMatch returns the number of common prefix bits.
// [startLen] is the number of bits we already know are shared between [node.ke] and [keyData].
func longestMatch[T any](startLen PrefixLen, node *lpmNode[T], keyData []byte, keyPrefixLen PrefixLen) PrefixLen {
	keySize := uint16(min(len(node.key), len(keyData)))
	startLenBytes := startLen / 8
	prefixLen := 8 * startLenBytes
	nodePrefixLen := node.prefixLen()
	minPrefixLen := min(nodePrefixLen, keyPrefixLen)
	for i := startLenBytes; i < keySize; i++ {
		matchLenInByte := bits.LeadingZeros8(node.key[i] ^ keyData[i])
		prefixLen += PrefixLen(matchLenInByte)
		if prefixLen >= minPrefixLen {
			return minPrefixLen
		}
		if matchLenInByte < 8 {
			// Less than full byte matched, we can stop.
			break
		}
	}
	return prefixLen
}

func lpmLookup[T any](root *lpmNode[T], key index.Key) (value T, ok bool) {
	keyData, keyPrefixLen := DecodeLPMKey(key)
	var closest *lpmNode[T]
	node := root
	currentLen := PrefixLen(0)
	for node != nil {
		nodePrefixLen := node.prefixLen()
		matchLen := longestMatch(currentLen, node, keyData, keyPrefixLen)
		if matchLen == keyPrefixLen {
			return node.value, !node.imaginary
		}
		if matchLen < nodePrefixLen {
			break
		}
		currentLen = nodePrefixLen
		if !node.imaginary {
			closest = node
		}
		node = node.children[getBitAt(keyData, nodePrefixLen)]
	}
	if closest != nil {
		return closest.value, true
	}
	return value, false
}

func lpmLookupExact[T any](root *lpmNode[T], key index.Key) (value T, ok bool) {
	node := root
	keyData, keyPrefixLen := DecodeLPMKey(key)
	var matchLen PrefixLen
	for node != nil {
		nodePrefixLen := node.prefixLen()
		matchLen = longestMatch(matchLen, node, keyData, keyPrefixLen)
		if matchLen == keyPrefixLen && matchLen == nodePrefixLen {
			if node.imaginary {
				return
			}
			return node.value, true
		}
		if matchLen < nodePrefixLen {
			break
		}
		node = node.children[getBitAt(keyData, nodePrefixLen)]
	}
	return
}

func getBitAt(data []byte, index uint16) int {
	return int(data[index/8]>>(7-(index%8))) & 1
}

func showKey(key index.Key) string {
	data, bits := DecodeLPMKey(key)
	totalBits := bits
	var w strings.Builder
	for i, b := range data {
		mask := byte(0xff)
		if bits < 8 {
			mask <<= (8 - bits)
		}
		fmt.Fprintf(&w, "%d", b&mask)
		if i != len(data)-1 {
			fmt.Fprint(&w, ".")
		}
		bits -= 8
	}
	fmt.Fprintf(&w, "/%d", totalBits)
	return w.String()
}
