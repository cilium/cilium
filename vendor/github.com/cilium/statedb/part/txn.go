// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package part

import (
	"bytes"
)

// Txn is a transaction against a tree. It allows doing efficient
// modifications to a tree by caching and reusing cloned nodes.
type Txn[T any] struct {
	root *header[T]
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
		opts: txn.opts,
		root: txn.root,
		size: txn.size,
		txn:  nil,
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
	if !hadOld {
		txn.size++
	}
	if txn.opts.rootOnlyWatch() {
		watch = txn.root.watch
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
	if !hadOld {
		txn.size++
	}
	if txn.opts.rootOnlyWatch() {
		watch = txn.root.watch
	}
	return
}

// Delete the given key from the tree.
// Returns the old value if it exists.
func (txn *Txn[T]) Delete(key []byte) (old T, hadOld bool) {
	old, hadOld, txn.root = txn.delete(txn.root, key)
	if hadOld {
		txn.size--
	}
	return
}

// RootWatch returns a watch channel for the root of the tree.
// Since this is the channel associated with the root, this closes
// when there are any changes to the tree.
func (txn *Txn[T]) RootWatch() <-chan struct{} {
	return txn.root.watch
}

// Get fetches the value associated with the given key.
// Returns the value, a watch channel (which is closed on
// modification to the key) and boolean which is true if
// value was found.
func (txn *Txn[T]) Get(key []byte) (T, <-chan struct{}, bool) {
	value, watch, ok := search(txn.root, key)
	if txn.opts.rootOnlyWatch() {
		watch = txn.root.watch
	}
	return value, watch, ok
}

// Prefix returns an iterator for all objects that starts with the
// given prefix, and a channel that closes when any objects matching
// the given prefix are upserted or deleted.
func (txn *Txn[T]) Prefix(key []byte) (*Iterator[T], <-chan struct{}) {
	txn.mutated.clear()
	iter, watch := prefixSearch(txn.root, key)
	if txn.opts.rootOnlyWatch() {
		watch = txn.root.watch
	}
	return iter, watch
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

// Commit the transaction and produce the new tree.
func (txn *Txn[T]) Commit() *Tree[T] {
	txn.Notify()
	return txn.CommitOnly()
}

// CommitOnly the transaction, but do not close the
// watch channels. Returns the new tree.
// To close the watch channels call Notify(). You must call Notify() before
// Tree.Txn().
func (txn *Txn[T]) CommitOnly() *Tree[T] {
	t := &Tree[T]{opts: txn.opts, root: txn.root, size: txn.size}
	if !txn.opts.noCache() {
		t.txn = txn
	}
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
	n = n.clone(!txn.opts.rootOnlyWatch() || n == txn.root)
	nodeMutatedSet(txn.mutated, n)
	return n
}

func (txn *Txn[T]) insert(root *header[T], key []byte, value T) (oldValue T, hadOld bool, watch <-chan struct{}, newRoot *header[T]) {
	return txn.modify(root, key, func(_ T) T { return value })
}

func (txn *Txn[T]) modify(root *header[T], key []byte, mod func(T) T) (oldValue T, hadOld bool, watch <-chan struct{}, newRoot *header[T]) {
	fullKey := key

	// Start recursing from the root to find the insertion point.
	// Point [thisp] to the root we're returning. It'll be replaced by a clone of the root when we recurse into it.
	this := root
	thisp := &newRoot

	// Try to insert the key into the tree. If we find a free slot into which to insert
	// it, we do it and return. If an existing node exists where the key should go, then
	// we stop. 'this' points to that node, and 'thisp' to its memory location. It has
	// not been cloned.
	for !this.isLeaf() && bytes.HasPrefix(key, this.prefix()) {
		// Prefix matched. Consume it and go further.
		key = key[this.prefixLen:]
		if len(key) == 0 {
			// Our key matches this node or we reached a leaf node.
			break
		}

		child, idx := this.findIndex(key[0])
		if child == nil {
			// We've found a free slot where to insert the key.
			if this.size()+1 > this.cap() {
				// Node too small, promote it to the next size.
				if this.watch != nil {
					txn.watches[this.watch] = struct{}{}
				}
				this = this.promote(!txn.opts.rootOnlyWatch() || this == root)
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
	if len(key) == 0 || len(key) == len(common) && len(key) == int(this.prefixLen) {
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
			leaf.value = mod(oldValue)
			watch = leaf.watch
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
	*thisp = this
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
		// target node has smaller key then new leaf
		newNode.children[0] = this
		newNode.keys[0] = this.key()
		newNode.children[1] = newLeaf.self()
		newNode.keys[1] = key[0]
		newNode.setSize(2)
	default:
		// new leaf has smaller key then target node
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
	// Reuse the same slice in the transaction to hold the parents in order to avoid
	// allocations. Pre-allocate 32 levels to cover most of the use-cases without
	// reallocation.
	if txn.deleteParentsCache == nil {
		txn.deleteParentsCache = make([]deleteParent[T], 0, 32)
	}
	parents := txn.deleteParentsCache[:1] // Placeholder for root

	newRoot = root
	this := root

	// Find the target node and record the path to it.
	var leaf *leaf[T]
	for {
		if bytes.HasPrefix(key, this.prefix()) {
			key = key[this.prefixLen:]
			if len(key) == 0 {
				leaf = this.getLeaf()
				if leaf == nil {
					return
				}
				// Target node found!
				break
			}
			var idx int
			this, idx = this.findIndex(key[0])
			if this == nil {
				return
			}
			parents = append(parents, deleteParent[T]{this, idx})
		} else {
			// Reached a node with a different prefix, so node not found.
			return
		}
	}

	oldValue = leaf.value
	hadOld = true

	// Mark the watch channel of the target for closing if not mutated already.
	if leaf.watch != nil {
		txn.watches[leaf.watch] = struct{}{}
	}

	if this == root {
		// Target is the root, clear it.
		if root.isLeaf() || newRoot.size() == 0 {
			// Replace leaf or empty root with a node4
			newRoot = newNode4[T]()
		} else {
			newRoot = txn.cloneNode(root)
			newRoot.setLeaf(nil)
		}
		return
	}

	// The target was found, rebuild the tree from the root upwards.
	parents[0].node = root

	for i := len(parents) - 1; i > 0; i-- {
		parent := &parents[i-1]
		target := &parents[i]

		// Clone the parent to mutate it.
		parent.node = txn.cloneNode(parent.node)
		children := parent.node.children()

		if target.node == this && target.node.size() > 0 {
			// This is the node that we want to delete, but it has
			// children. Clone and clear the leaf.
			target.node = txn.cloneNode(target.node)
			target.node.setLeaf(nil)
			children[target.index] = target.node
		} else if target.node.size() == 0 && (target.node == this || target.node.getLeaf() == nil) {
			// The node is empty, remove it from the parent.
			parent.node.remove(target.index)
		} else {
			// Update the target (as it may have been cloned)
			children[target.index] = target.node
		}

		if parent.node.size() > 0 {
			// Check if the node should be demoted.
			// To avoid thrashing we don't demote at the boundary, but at a slightly
			// smaller size.
			// TODO: Can we avoid the initial clone of parent.node?
			var newNode *header[T]
			switch {
			case parent.node.kind() == nodeKind256 && parent.node.size() <= 37:
				newNode = (&node48[T]{header: *parent.node}).self()
				newNode.setKind(nodeKind48)
				n48 := newNode.node48()
				n48.leaf = parent.node.getLeaf()
				children := n48.children[:0]
				for k, n := range parent.node.node256().children[:] {
					if n != nil {
						n48.index[k] = int8(len(children))
						children = append(children, n)
					}
				}
			case parent.node.kind() == nodeKind48 && parent.node.size() <= 12:
				newNode = (&node16[T]{header: *parent.node}).self()
				newNode.setKind(nodeKind16)
				copy(newNode.children()[:], parent.node.children())
				n16 := newNode.node16()
				n16.leaf = parent.node.getLeaf()
				size := n16.size()
				for i := range size {
					n16.keys[i] = n16.children[i].key()
				}
			case parent.node.kind() == nodeKind16 && parent.node.size() <= 3:
				newNode = (&node4[T]{header: *parent.node}).self()
				newNode.setKind(nodeKind4)
				n16 := parent.node.node16()
				size := n16.size()
				n4 := newNode.node4()
				n4.leaf = n16.leaf
				copy(n4.children[:], n16.children[:size])
				copy(n4.keys[:], n16.keys[:size])
			}
			if newNode != nil {
				parent.node = newNode
			}
		}
	}
	newRoot = parents[0].node
	return
}
