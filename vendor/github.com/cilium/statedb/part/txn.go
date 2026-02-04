// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package part

import (
	"bytes"
	"fmt"
	"os"
	"slices"
	"sync/atomic"
)

// Txn is a transaction against a tree. It allows doing efficient
// modifications to a tree by caching and reusing cloned nodes.
type Txn[T any] struct {
	root      *header[T]
	oldRoot   *header[T]
	rootWatch chan struct{}
	prevTxn   *atomic.Pointer[Txn[T]]

	dirty bool

	opts options

	// the number of objects in the tree
	size int

	// txnID is a monotonically increasing integer that is assigned when the Txn
	// is created from a [Tree] and is used to detect whether a node has been
	// cloned during this transaction or not to allow mutating it in place.
	// txnID is also incremented when returning an iterator in order to not
	// mutate the tree used by the iterator as that would mess up iteration.
	txnID uint64

	// watches contains the channels of cloned nodes that should be closed
	// when transaction is committed.
	watches map[chan struct{}]struct{}

	// deleteParentsCache keeps the last allocated slice to avoid
	// reallocating it on every deletion.
	deleteParentsCache []deleteParent[T]
}

// Len returns the number of objects in the tree.
func (txn *Txn[T]) Len() int {
	return txn.size
}

func (txn *Txn[T]) All(yield func([]byte, T) bool) {
	// Bump txnID in order to freeze the current tree.
	txn.txnID++
	Iterator[T]{start: txn.root}.All(yield)
}

// Clone returns a clone of the transaction for reading. The clone is unaffected
// by any future changes done with the original transaction.
func (txn *Txn[T]) Clone() Tree[T] {
	// Invalidate in-place mutations so the returned clone won't be changed by
	// further modifications in this transaction.
	txn.txnID++
	return Tree[T]{
		opts:      txn.opts,
		root:      txn.root,
		rootWatch: txn.rootWatch,
		size:      txn.size,
		prevTxn:   txn.prevTxn,
		nextTxnID: txn.txnID,
	}
}

// Insert or update the tree with the given key and value.
// Returns the old value if it exists.
func (txn *Txn[T]) Insert(key []byte, value T) (old T, hadOld bool) {
	old, hadOld, _ = txn.InsertWatch(key, value)
	return
}

// Insert or update the tree with the given key and value.
// Returns the old value if it exists and a watch channel that closes when the
// key changes again.
func (txn *Txn[T]) InsertWatch(key []byte, value T) (old T, hadOld bool, watch <-chan struct{}) {
	old, _, hadOld, watch, txn.root = txn.insert(txn.root, key, value)
	validateTree(txn.root, nil, txn.watches, txn.txnID)
	if !hadOld {
		txn.size++
	}
	if txn.opts.rootOnlyWatch() {
		watch = txn.rootWatch
	}
	return
}

// Modify a value in the tree. It is up to the
// caller to not mutate the value in-place and to return a clone.
// Returns the old value (if it exists) and the new possibly merged value.
func (txn *Txn[T]) Modify(key []byte, value T, mod func(T, T) T) (old T, newValue T, hadOld bool) {
	old, newValue, hadOld, _ = txn.ModifyWatch(key, value, mod)
	return
}

// Modify a value in the tree. If the key does not exist the modify
// function is called with the zero value for T. It is up to the
// caller to not mutate the value in-place and to return a clone.
// Returns the old value (if it exists) and the new possibly merged value,
// and a watch channel that closes when the key changes again.
func (txn *Txn[T]) ModifyWatch(key []byte, value T, mod func(T, T) T) (old T, newValue T, hadOld bool, watch <-chan struct{}) {
	old, newValue, hadOld, watch, txn.root = txn.modify(txn.root, key, value, mod)
	validateTree(txn.root, nil, txn.watches, txn.txnID)
	if !hadOld {
		txn.size++
	}
	if txn.opts.rootOnlyWatch() {
		watch = txn.rootWatch
	}
	return
}

// Delete the given key from the tree.
// Returns the old value if it exists.
func (txn *Txn[T]) Delete(key []byte) (old T, hadOld bool) {
	old, hadOld, txn.root = txn.delete(txn.root, key)
	validateTree(txn.root, nil, txn.watches, txn.txnID)
	if hadOld {
		txn.size--
	}
	return
}

// RootWatch returns a watch channel for the root of the tree.
// Since this is the channel associated with the root, this closes
// when there are any changes to the tree.
func (txn *Txn[T]) RootWatch() <-chan struct{} {
	return txn.rootWatch
}

// Get fetches the value associated with the given key.
// Returns the value, a watch channel (which is closed on
// modification to the key) and boolean which is true if
// value was found.
func (txn *Txn[T]) Get(key []byte) (T, <-chan struct{}, bool) {
	value, watch, ok := search(txn.root, txn.rootWatch, key)
	return value, watch, ok
}

// Prefix returns an iterator for all objects that starts with the
// given prefix, and a channel that closes when any objects matching
// the given prefix are upserted or deleted.
func (txn *Txn[T]) Prefix(key []byte) (Iterator[T], <-chan struct{}) {
	// Bump txnID in order to freeze the current tree.
	txn.txnID++
	return prefixSearch(txn.root, txn.rootWatch, key)
}

// LowerBound returns an iterator for all objects that have a
// key equal or higher than the given 'key'.
func (txn *Txn[T]) LowerBound(key []byte) Iterator[T] {
	// Bump txnID in order to freeze the current tree.
	txn.txnID++
	return lowerbound(txn.root, key)
}

// Iterator returns an iterator for all objects.
func (txn *Txn[T]) Iterator() Iterator[T] {
	// Bump txnID in order to freeze the current tree.
	txn.txnID++
	return newIterator(txn.root)
}

// CommitAndNotify commits the transaction and notifies by
// closing the watch channels of all modified nodes.
func (txn *Txn[T]) CommitAndNotify() Tree[T] {
	txn.Notify()
	return txn.Commit()
}

// Commit the transaction, but do not close the
// watch channels. Returns the new tree.
// To close the watch channels call Notify(). You must call Notify() before
// Tree.Txn().
func (txn *Txn[T]) Commit() Tree[T] {
	newRootWatch := txn.rootWatch
	if txn.dirty {
		newRootWatch = make(chan struct{})
		validateTree(txn.oldRoot, nil, nil, txn.txnID)
		validateTree(txn.root, nil, txn.watches, txn.txnID)
	}
	txn.txnID++
	t := Tree[T]{
		opts:      txn.opts,
		root:      txn.root,
		rootWatch: newRootWatch,
		size:      txn.size,
		prevTxn:   txn.prevTxn,
		nextTxnID: txn.txnID,
	}
	// Store this txn in the tree to reuse the allocation next time.
	t.prevTxn.Store(txn)
	return t
}

// Notify closes the watch channels of nodes that were
// mutated as part of this transaction. Must be called before
// Tree.Txn() is used again.
func (txn *Txn[T]) Notify() {
	for ch := range txn.watches {
		close(ch)
	}
	clear(txn.watches)
	if !txn.dirty && len(txn.watches) > 0 {
		panic("BUG: watch channels marked but txn not dirty")
	}
	if txn.dirty && txn.rootWatch != nil {
		close(txn.rootWatch)
		txn.rootWatch = nil
	}
	if !txn.opts.rootOnlyWatch() {
		validateRemovedWatches(txn.oldRoot, txn.root)
	}
}

// PrintTree to the standard output. For debugging.
func (txn *Txn[T]) PrintTree() {
	txn.root.printTree(0)
	fmt.Printf("watches: ")
	for watch := range txn.watches {
		fmt.Printf("%p ", watch)
	}
	fmt.Println()
}

func (txn *Txn[T]) cloneNode(n *header[T]) *header[T] {
	if n.txnID() == txn.txnID {
		// The node was already cloned during this transaction and can
		// be mutated in-place.
		return n
	}
	if n.watch != nil {
		txn.watches[n.watch] = struct{}{}
	}
	n = n.clone(!txn.opts.rootOnlyWatch())
	n.setTxnID(txn.txnID)
	return n
}

func (txn *Txn[T]) insert(root *header[T], key []byte, value T) (oldValue T, newValue T, hadOld bool, watch <-chan struct{}, newRoot *header[T]) {
	return txn.modify(root, key, value, nil)
}

func (txn *Txn[T]) modify(root *header[T], key []byte, newValue T, mod func(T, T) T) (oldValue T, newValueOut T, hadOld bool, watch <-chan struct{}, newRoot *header[T]) {
	txn.dirty = true
	fullKey := key
	newValueOut = newValue

	if root == nil {
		leaf := newLeaf(txn.opts, key, fullKey, newValue)
		return oldValue, newValueOut, false, leaf.watch, leaf.self()
	}

	// Start recursing from the root to find the insertion point.
	// Point [thisp] to the root we're returning. It'll be replaced by a clone of the root when we recurse into it.
	this := root
	newRoot = root
	thisp := &newRoot

	// Try to insert the key into the tree. If we find a free slot into which to insert
	// it, we do it and return. If an existing node exists where the key should go, then
	// we stop. 'this' points to that node, and 'thisp' to its memory location. It has
	// not been cloned.
	for len(key) > 0 && !this.isLeaf() && bytes.HasPrefix(key, this.prefix()) {
		if len(key) == int(this.prefixLen) {
			// Exact match
			break
		}

		// Prefix matched. Consume it and go further.
		key = key[this.prefixLen:]

		child, idx := this.findIndex(key[0])
		if child == nil {
			// We've found a free slot where to insert the key.
			if this.size()+1 > this.cap() {
				// Node too small, promote it to the next size.
				if this.watch != nil {
					txn.watches[this.watch] = struct{}{}
				}
				this = this.promote(txn.txnID)
			} else {
				// Node is big enough, clone it so we can mutate it
				this = txn.cloneNode(this)
			}
			leaf := newLeaf(txn.opts, key, fullKey, newValue)
			this.insert(idx, leaf.self())
			*thisp = this
			watch = leaf.watch
			return
		}

		// Clone the parent so we can modify it
		this = txn.cloneNode(this)
		*thisp = this
		// And recurse into the child
		thisp = &this.children()[idx]
		this = *thisp
	}

	common := commonPrefix(key, this.prefix())

	// A node already exists where we wanted to insert the key.
	// 'this' points to it, and 'thisp' is its memory location. The parents
	// have been cloned.
	//
	// Check first if it's an exact match.
	if len(key) == len(common) && len(key) == int(this.prefixLen) {
		this = txn.cloneNode(this)
		*thisp = this
		if leaf := this.getLeaf(); leaf != nil {
			oldValue = leaf.value
			hadOld = true
			if !this.isLeaf() {
				// [this] is a non-leaf node, clone its leaf so we can update it.
				leaf = txn.cloneNode(leaf.self()).getLeaf()
				this.setLeaf(leaf)
			}
			watch = leaf.watch
			if mod != nil {
				newValueOut = mod(oldValue, newValue)
				leaf.value = newValueOut
			} else {
				leaf.value = newValue
			}
		} else {
			// Set the leaf
			leaf := newLeaf(txn.opts, this.prefix(), fullKey, newValue)
			watch = leaf.watch
			this.setLeaf(leaf)
		}
		return
	}

	// The target node into which we want to insert has only a partially matching prefix.
	// We'll replace target with a new [node4] and insert the target and new node into it
	// (either as children or as leaf, depending on the prefixes).
	if this.isLeaf() {
		// We're replacing a leaf node, make a shallow copy to retain
		// its watch channel since we're just manipulating prefix.
		leafCopy := *this.getLeaf()
		this = &leafCopy.header
	} else {
		this = txn.cloneNode(this)
	}
	this.setPrefix(this.prefix()[len(common):])
	key = key[len(common):]

	newLeaf := newLeaf(txn.opts, key, fullKey, newValue)
	watch = newLeaf.watch
	newNode := &node4[T]{}
	newNode.txnID = txn.txnID
	newNode.setPrefix(common)
	newNode.setKind(nodeKind4)
	if !txn.opts.rootOnlyWatch() {
		newNode.watch = make(chan struct{})
	}

	switch {
	case this.prefixLen == 0:
		// target has shorter key than new leaf
		newNode.setLeaf(this.getLeaf())
		newNode.children[0] = newLeaf.self()
		newNode.keys[0] = key[0]
		newNode.setSize(1)

	case len(key) == 0:
		// new leaf has shorter key than target
		newNode.setLeaf(newLeaf)
		newNode.children[0] = this
		newNode.keys[0] = this.key()
		newNode.setSize(1)

	case this.key() < key[0]:
		// target node has smaller key than new leaf
		newNode.children[0] = this
		newNode.keys[0] = this.key()
		newNode.children[1] = newLeaf.self()
		newNode.keys[1] = key[0]
		newNode.setSize(2)
	default:
		// new leaf has smaller key than target node
		newNode.children[0] = newLeaf.self()
		newNode.keys[0] = key[0]
		newNode.children[1] = this
		newNode.keys[1] = this.key()
		newNode.setSize(2)
	}
	*thisp = newNode.self()

	return
}

// deleteParent tracks a node on the path to the target node that is being
// deleted.
type deleteParent[T any] struct {
	node  *header[T]
	index int // the index of this node at its parent
}

func (txn *Txn[T]) delete(root *header[T], key []byte) (oldValue T, hadOld bool, newRoot *header[T]) {
	if root == nil {
		return
	}

	// Reuse the same slice in the transaction to hold the parents in order to avoid
	// allocations. Pre-allocate 32 levels to cover most of the use-cases without
	// reallocation.
	if txn.deleteParentsCache == nil {
		txn.deleteParentsCache = make([]deleteParent[T], 0, 32)
	}
	parents := txn.deleteParentsCache[:1] // Placeholder for root
	parents[0].node = root

	newRoot = root
	target := root

	// Find the target node and record the path to it.
	var leaf *leaf[T]
	for {
		if bytes.HasPrefix(key, target.prefix()) {
			key = key[target.prefixLen:]
			if len(key) == 0 {
				leaf = target.getLeaf()
				if leaf == nil {
					return
				}
				// Target node found!
				break
			}
			var idx int
			target, idx = target.findIndex(key[0])
			if target == nil {
				return
			}
			parents = append(parents, deleteParent[T]{target, idx})
		} else {
			// Reached a node with a different prefix, so node not found.
			return
		}
	}

	txn.dirty = true

	oldValue = leaf.value
	hadOld = true

	// Mark the watch channel of the target for closing.
	if leaf.watch != nil {
		txn.watches[leaf.watch] = struct{}{}
	}

	if target == root {
		switch {
		case root.isLeaf() || root.size() == 0:
			if root.watch != nil {
				txn.watches[root.watch] = struct{}{}
			}
			// Root is a leaf or node without children
			newRoot = nil
		case root.size() == 1:
			if root.watch != nil {
				txn.watches[root.watch] = struct{}{}
			}
			// Root is a non-leaf node with single child. We can replace
			// the root with the child.
			child := root.children()[0]
			childClone := child.clone(false)
			childClone.watch = child.watch
			childClone.setPrefix(slices.Concat(root.prefix(), childClone.prefix()))
			newRoot = childClone
		default:
			// Root is a non-leaf node with many children. Just drop the leaf.
			newRoot = txn.cloneNode(root)
			newRoot.setLeaf(nil)
		}
		return
	}

	// The target was found, rebuild the tree from the leaf upwards to the root.
	index := len(parents) - 1
	this := &parents[index]
	parent := &parents[index-1]
	index--
	oldParent := parent.node
	if this.node.size() == 1 {
		// The target node is not a leaf node and has only a single
		// child. Shift the child up.
		if this.node.watch != nil {
			txn.watches[this.node.watch] = struct{}{}
		}
		child := this.node.children()[0]
		childClone := child.clone(false)
		childClone.watch = child.watch
		childClone.setPrefix(slices.Concat(this.node.prefix(), childClone.prefix()))
		parent.node = txn.cloneNode(parent.node)
		parent.node.children()[this.index] = childClone
	} else if this.node.size() > 0 {
		// The target node is not a leaf node and has children.
		// Drop the leaf.
		this.node = txn.cloneNode(this.node)
		this.node.setLeaf(nil)
		parent.node = txn.cloneNode(parent.node)
		parent.node.children()[this.index] = this.node
	} else {
		// The target node is a leaf node or a non-leaf node without any
		// children. We can just drop it from the parent.
		if this.node.watch != nil {
			txn.watches[this.node.watch] = struct{}{}
		}
		parent.node = txn.removeChild(parent.node, this.index)
	}

	if parent.node == oldParent && parent.node.txnID() == txn.txnID {
		// The parent had already been cloned during this transaction so no need to
		// rebuild the root as we're already pointing to new nodes.
		newRoot = parents[0].node
		return
	}

	// Update the child pointers all the way up to the root.
	for index > 0 {
		parent = &parents[index-1]
		this = &parents[index]
		oldParent = parent.node
		if this.node == nil {
			// Node is gone, can remove it completely.
			parent.node = txn.removeChild(parent.node, this.index)
		} else {
			children := parent.node.children()
			if children[this.index] != this.node {
				parent.node = txn.cloneNode(parent.node)
				parent.node.children()[this.index] = this.node
			}
		}
		if parent.node == oldParent && parent.node.txnID() == txn.txnID {
			// The parent had already been cloned during this transaction so no need to
			// rebuild the root as we're already pointing to new nodes.
			newRoot = parents[0].node
			return
		}
		index--
	}

	newRoot = parents[0].node
	return
}

func (txn *Txn[T]) removeChild(parent *header[T], index int) (newParent *header[T]) {
	size := parent.size()
	switch {
	case size == 2 && parent.getLeaf() == nil:
		// Only one child remains and no leaf. Replace the node with the
		// remaining child.
		if parent.kind() != nodeKind4 {
			panic("expected node4")
		}
		remainingIndex := 0
		if index == 0 {
			remainingIndex = 1
		}

		if parent.watch != nil {
			txn.watches[parent.watch] = struct{}{}
		}

		child := parent.node4().children[remainingIndex]
		// Clone for prefix adjustment, but leave watch alone.
		// The node must not be treated as writable since we didn't clone
		// the watch.
		childClone := child.clone(false)
		childClone.watch = child.watch
		childClone.setPrefix(slices.Concat(parent.prefix(), childClone.prefix()))
		return childClone

	case parent.kind() == nodeKind256 && size <= 49:
		demoted := (&node48[T]{header: *parent}).self()
		if parent.watch != nil {
			demoted.watch = make(chan struct{})
		}
		demoted.setKind(nodeKind48)
		demoted.setSize(size - 1)
		demoted.setTxnID(txn.txnID)
		n48 := demoted.node48()
		n48.leaf = parent.getLeaf()
		children := n48.children[:0]
		for k, n := range parent.node256().children[:] {
			if k != index && n != nil {
				n48.index[k] = int8(len(children))
				children = append(children, n)
			}
		}
		newParent = demoted
	case parent.kind() == nodeKind48 && size <= 17:
		demoted := (&node16[T]{header: *parent}).self()
		if parent.watch != nil {
			demoted.watch = make(chan struct{})
		}
		demoted.setKind(nodeKind16)
		demoted.setSize(size - 1)
		demoted.setTxnID(txn.txnID)
		n16 := demoted.node16()
		n16.leaf = parent.getLeaf()
		idx := 0
		for i, child := range parent.children() {
			if i != index {
				n16.children[idx] = child
				n16.keys[idx] = child.key()
				idx++
			}
		}
		newParent = demoted
	case parent.kind() == nodeKind16 && size <= 5:
		demoted := (&node4[T]{header: *parent}).self()
		if parent.watch != nil {
			demoted.watch = make(chan struct{})
		}
		demoted.setKind(nodeKind4)
		demoted.setSize(size - 1)
		demoted.setTxnID(txn.txnID)
		n16 := parent.node16()
		n4 := demoted.node4()
		n4.leaf = n16.leaf
		idx := 0
		for i := range size {
			if i != index {
				n4.children[idx] = n16.children[i]
				n4.keys[idx] = n16.keys[i]
				idx++
			}
		}
		newParent = demoted
	default:
		newParent = txn.cloneNode(parent)
		newParent.remove(index)
		return newParent
	}
	if parent.watch != nil {
		txn.watches[parent.watch] = struct{}{}
	}
	return newParent
}

var runValidation = os.Getenv("STATEDB_VALIDATE") != ""

// validateTree checks that the resulting tree is well-formed and panics
// if it is not.
func validateTree[T any](node *header[T], parents []*header[T], watches map[chan struct{}]struct{}, maxTxnID uint64) {
	if !runValidation {
		return
	}

	if node == nil {
		return
	}
	assert := func(b bool, f string, args ...any) {
		if !b {
			node.printTree(0)
			panic(fmt.Sprintf(f, args...))
		}
	}

	// A leaf node's key is the sum of all prefixes in path
	if leaf := node.getLeaf(); leaf != nil {
		var fullKey []byte
		for _, p := range parents {
			fullKey = append(fullKey, p.prefix()...)
		}
		fullKey = append(fullKey, node.prefix()...)

		assert(bytes.Equal(leaf.fullKey(), fullKey),
			"leaf's key does not match sum of prefixes, expected %x, got %x",
			leaf.fullKey(), fullKey)

		// If a leaf's watch channel is to be closed then parent's should be
		// marked closed too. The case where node is a leaf is handled below.
		if !node.isLeaf() {
			if _, found := watches[leaf.watch]; found {
				_, found := watches[node.watch]
				assert(found, "node's watch channel not marked for closing when leaf is")
			}
		}
	}

	// txnID must never exceed the max seen in this transaction.
	if maxTxnID > 0 {
		nodeTxnID := node.txnID()
		assert(nodeTxnID <= maxTxnID, "node txnID %d exceeds max %d", nodeTxnID, maxTxnID)
	}

	if len(parents) > 0 {
		parent := parents[len(parents)-1]
		parentTxnID := parent.txnID()
		nodeTxnID := node.txnID()
		assert(parentTxnID >= nodeTxnID, "parent txnID %d < child txnID %d", parentTxnID, nodeTxnID)
	}

	// Nodes without a leaf must have size 2 or greater.
	assert(node.getLeaf() != nil || node.size() > 1,
		"node with single child has no leaf")

	// Node16 must have occupancy higher than 4
	assert(node.kind() != nodeKind16 || node.size() > 4, "node16 has fewer children than 5")

	// Node48 must have occupancy higher than 16
	assert(node.kind() != nodeKind48 || node.size() > 16, "node48 has fewer children than 17")

	// Node256 must have occupancy higher than 48
	assert(node.kind() != nodeKind256 || node.size() > 48, "node256 has fewer children than 49")

	// Nodes that have a watch channel that is to be closed must
	// also have all their parent's watch channels to be closed.
	if _, found := watches[node.watch]; found {
		select {
		case <-node.watch:
			panic("node's watch channel marked for closing but is already closed!")
		default:
		}
		for i, p := range parents {
			_, found := watches[p.watch]
			if !found {
				p.printTree(0)
				panic(fmt.Sprintf("parent %p (%d) watch channel (%p) not marked for closing (child %p, watch %p)", p, i, p.watch, node, node.watch))
			}

		}
	}

	// If a node's watch channel is closed then all the parents must be
	// closed as well.
	select {
	case <-node.watch:
		for _, p := range parents {
			select {
			case <-p.watch:
			default:
				p.printTree(0)
				panic(fmt.Sprintf("parent watch channel (%p) not marked for closing (child %p)", p.watch, node.watch))
			}
		}
	default:
	}

	parents = append(parents, node)

	for _, child := range node.children() {
		if child != nil {
			validateTree(child, parents, watches, maxTxnID)
		}
	}
}

func validateRemovedWatches[T any](oldRoot *header[T], newRoot *header[T]) {
	if !runValidation {
		return
	}

	// nodeStruct memoizes the structure for a node.
	nodeStruct := map[*header[T]]string{}

	// summarizeNodeStructure "lazily" summarizes the internal structure of a node,
	// e.g. it's watch channel, size, leaf and children. The lazy construction speeds
	// things up a lot as we only look at the structure in certain specific cases.
	var summarizeNodeStructure func(node *header[T]) func() string
	summarizeNodeStructure = func(node *header[T]) func() string {
		if node == nil {
			return func() string { return "" }
		}
		if s, found := nodeStruct[node]; found {
			return func() string { return s }
		}
		return func() string {
			var childS string
			for _, child := range node.children() {
				if child != nil {
					childS += summarizeNodeStructure(child)()
				}
			}
			var leafS string
			if leaf := node.getLeaf(); leaf != nil && !node.isLeaf() {
				leafS = summarizeNodeStructure(leaf.self())()
			}
			s := fmt.Sprintf("K:%d S:%d W:%p L:[%s] C:[%s]", node.kind(), node.size(), node.watch, leafS, childS)
			nodeStruct[node] = s
			return s
		}
	}

	var collectWatches func(depth int, watches map[<-chan struct{}]func() string, node *header[T])
	collectWatches = func(depth int, watches map[<-chan struct{}]func() string, node *header[T]) {
		if node == nil {
			return
		}
		if node.watch == nil {
			panic("nil watch channel")
		}
		watches[node.watch] = summarizeNodeStructure(node)
		if leaf := node.getLeaf(); leaf != nil && !node.isLeaf() {
			watches[leaf.watch] = summarizeNodeStructure(leaf.self())
		}
		for _, child := range node.children() {
			if child != nil {
				collectWatches(depth+1, watches, child)
			}
		}
	}

	oldWatches := map[<-chan struct{}]func() string{}
	collectWatches(0, oldWatches, oldRoot)
	newWatches := map[<-chan struct{}]func() string{}
	collectWatches(0, newWatches, newRoot)

	// Check that any nodes that kept the old watch channel have exactly
	// the same leaf and children structure.
	for watch, oldDescFn := range oldWatches {
		newDescFn, found := newWatches[watch]
		if found {
			oldDesc := oldDescFn()
			newDesc := newDescFn()
			if oldDesc != newDesc {
				panic(fmt.Sprintf("node with retained watch channel has different structure:\nexpected: %s\n     got: %s", oldDesc, newDesc))
			}
		}

	}

	// Any nodes that are not part of the new tree must have their watch channels closed.
	for watch := range newWatches {
		delete(oldWatches, watch)
	}

	for watch, desc := range oldWatches {
		select {
		case <-watch:
		default:
			oldRoot.printTree(0)
			fmt.Println("---")
			newRoot.printTree(0)
			panic(fmt.Sprintf("dropped watch channel %p not closed %s", watch, desc()))
		}
	}
}
