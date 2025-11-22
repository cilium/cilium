// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package part

import (
	"bytes"
	"fmt"
	"os"
	"slices"
)

// Txn is a transaction against a tree. It allows doing efficient
// modifications to a tree by caching and reusing cloned nodes.
type Txn[T any] struct {
	oldRoot   *header[T]
	root      *header[T]
	rootWatch chan struct{}

	dirty bool

	opts options
	size int // the number of objects in the tree

	// mutated is the set of nodes mutated in this transaction
	// that we can keep mutating without cloning them again.
	// It is cleared if the transaction is cloned or iterated
	// upon.
	mutated *nodeMutated

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

// Clone returns a clone of the transaction for reading. The clone is unaffected
// by any future changes done with the original transaction.
func (txn *Txn[T]) Clone() Ops[T] {
	// Clear the mutated nodes so that the returned clone won't be changed by
	// further modifications in this transaction.
	txn.mutated.clear()
	return &Tree[T]{
		opts:      txn.opts,
		root:      txn.root,
		rootWatch: txn.rootWatch,
		size:      txn.size,
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
	old, hadOld, watch, txn.root = txn.insert(txn.root, key, value)
	validateTree(txn.root, nil, txn.watches)
	if !hadOld {
		txn.size++
	}
	if txn.opts.rootOnlyWatch() {
		watch = txn.rootWatch
	}
	return
}

// Modify a value in the tree. If the key does not exist the modify
// function is called with the zero value for T. It is up to the
// caller to not mutate the value in-place and to return a clone.
// Returns the old value if it exists.
func (txn *Txn[T]) Modify(key []byte, mod func(T) T) (old T, hadOld bool) {
	old, hadOld, _ = txn.ModifyWatch(key, mod)
	return
}

// Modify a value in the tree. If the key does not exist the modify
// function is called with the zero value for T. It is up to the
// caller to not mutate the value in-place and to return a clone.
// Returns the old value if it exists and a watch channel that closes
// when the key changes again.
func (txn *Txn[T]) ModifyWatch(key []byte, mod func(T) T) (old T, hadOld bool, watch <-chan struct{}) {
	old, hadOld, watch, txn.root = txn.modify(txn.root, key, mod)
	validateTree(txn.root, nil, txn.watches)
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
	validateTree(txn.root, nil, txn.watches)
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
func (txn *Txn[T]) Prefix(key []byte) (*Iterator[T], <-chan struct{}) {
	txn.mutated.clear()
	return prefixSearch(txn.root, txn.rootWatch, key)
}

// LowerBound returns an iterator for all objects that have a
// key equal or higher than the given 'key'.
func (txn *Txn[T]) LowerBound(key []byte) *Iterator[T] {
	txn.mutated.clear()
	return lowerbound(txn.root, key)
}

// Iterator returns an iterator for all objects.
func (txn *Txn[T]) Iterator() *Iterator[T] {
	txn.mutated.clear()
	return newIterator(txn.root)
}

// CommitAndNotify commits the transaction and notifies by
// closing the watch channels of all modified nodes.
func (txn *Txn[T]) CommitAndNotify() *Tree[T] {
	txn.Notify()
	return txn.Commit()
}

// Commit the transaction, but do not close the
// watch channels. Returns the new tree.
// To close the watch channels call Notify(). You must call Notify() before
// Tree.Txn().
func (txn *Txn[T]) Commit() *Tree[T] {
	newRootWatch := txn.rootWatch
	if txn.dirty {
		newRootWatch = make(chan struct{})
		validateTree(txn.oldRoot, nil, nil)
		validateTree(txn.root, nil, txn.watches)
	}
	t := &Tree[T]{
		opts:      txn.opts,
		root:      txn.root,
		rootWatch: newRootWatch,
		size:      txn.size,
	}
	txn.mutated.clear()
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
	if txn.dirty && txn.rootWatch != nil {
		close(txn.rootWatch)
		txn.rootWatch = nil
	}
}

// PrintTree to the standard output. For debugging.
func (txn *Txn[T]) PrintTree() {
	txn.root.printTree(0)
}

func (txn *Txn[T]) cloneNode(n *header[T]) *header[T] {
	if nodeMutatedExists(txn.mutated, n) {
		return n
	}
	if n.watch != nil {
		txn.watches[n.watch] = struct{}{}
	}
	n = n.clone(!txn.opts.rootOnlyWatch())
	nodeMutatedSet(txn.mutated, n)
	return n
}

func (txn *Txn[T]) insert(root *header[T], key []byte, value T) (oldValue T, hadOld bool, watch <-chan struct{}, newRoot *header[T]) {
	return txn.modify(root, key, func(_ T) T { return value })
}

func (txn *Txn[T]) modify(root *header[T], key []byte, mod func(T) T) (oldValue T, hadOld bool, watch <-chan struct{}, newRoot *header[T]) {
	txn.dirty = true
	fullKey := key

	if root == nil {
		var zero T
		leaf := newLeaf(txn.opts, key, fullKey, mod(zero))
		return zero, false, leaf.watch, leaf.self()
	}

	// Start recursing from the root to find the insertion point.
	// Point [thisp] to the root we're returning. It'll be replaced by a clone of the root when we recurse into it.
	this := root
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
				this = this.promote()
				nodeMutatedSet(txn.mutated, this)
			} else {
				// Node is big enough, clone it so we can mutate it
				this = txn.cloneNode(this)
			}
			var zero T
			leaf := newLeaf(txn.opts, key, fullKey, mod(zero))
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
			leaf.value = mod(oldValue)
		} else {
			// Set the leaf
			var zero T
			leaf := newLeaf(txn.opts, this.prefix(), fullKey, mod(zero))
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

	var zero T
	newLeaf := newLeaf(txn.opts, key, fullKey, mod(zero))
	watch = newLeaf.watch
	newNode := &node4[T]{}
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
	nodeMutatedSet(txn.mutated, newNode.self())

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

	// Mark the watch channel of the target for closing if not mutated already.
	if leaf.watch != nil {
		txn.watches[leaf.watch] = struct{}{}
	}

	if target == root {
		switch {
		case root.isLeaf() || root.size() == 0:
			// Root is a leaf or node without children
			newRoot = nil
		case root.size() == 1:
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
	parents[0].node = root
	index := len(parents) - 1
	this := &parents[index]
	parent := &parents[index-1]
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
		parent.node = txn.removeChild(parent.node, this.index)
	}
	index--

	// Update the child pointers all the way up to the root.
	for index > 0 {
		parent = &parents[index-1]
		this = &parents[index]
		if this.node == nil {
			// Node is gone, can remove it completely.
			parent.node = txn.removeChild(parent.node, this.index)
		} else {
			parent.node = txn.cloneNode(parent.node)
			parent.node.children()[this.index] = this.node
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

		child := parent.node4().children[remainingIndex]
		// Clone for prefix adjustment, but leave watch alone.
		childClone := child.clone(false)
		childClone.watch = child.watch
		childClone.setPrefix(slices.Concat(parent.prefix(), childClone.prefix()))
		newParent = childClone

	case parent.kind() == nodeKind256 && size <= 49:
		demoted := (&node48[T]{header: *parent}).self()
		if parent.watch != nil {
			demoted.watch = make(chan struct{})
		}
		demoted.setKind(nodeKind48)
		demoted.setSize(size - 1)
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
	nodeMutatedSet(txn.mutated, newParent)
	return newParent
}

var runValidation = os.Getenv("PART_VALIDATE") != ""

// validateTree checks that the resulting tree is well-formed and panics
// if it is not.
func validateTree[T any](node *header[T], parents []*header[T], watches map[chan struct{}]struct{}) {
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

	// Nodes without a leaf must have size 2 or greater.
	assert(node.getLeaf() != nil || node.size() > 1,
		"node with single child has no leaf")

	// Node16 must have occupancy higher than 4
	assert(node.kind() != nodeKind256 || node.size() > 4, "node16 has fewer children than 17")

	// Node48 must have occupancy higher than 16
	assert(node.kind() != nodeKind256 || node.size() > 16, "node48 has fewer children than 17")

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
			validateTree(child, parents, watches)
		}
	}
}
