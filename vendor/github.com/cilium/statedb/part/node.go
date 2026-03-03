// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package part

import (
	"bytes"
	"fmt"
	"strings"
	"unsafe"
)

type nodeKind uint8

const (
	nodeKindUnknown = iota
	nodeKindLeaf
	nodeKind4
	nodeKind16
	nodeKind48
	nodeKind256
)

// header is the common header shared by all node kinds.
type header[T any] struct {
	flags     uint16 // kind(4b) | unused(3b) | size(9b)
	prefixLen uint16
	prefixP   *byte         // the compressed prefix, [0] is the key
	watch     chan struct{} // watch channel that is closed when this node mutates
}

func (n *header[T]) key() byte {
	return *n.prefixP
}

func (n *header[T]) prefix() []byte {
	return unsafe.Slice(n.prefixP, n.prefixLen)
}

func (n *header[T]) isPrefixOf(key []byte) bool {
	// This is essentially same as bytes.HasPrefix(key, this.prefix()), but slight bit
	// faster as we don't need to construct the slice header for length comparison.
	return uint16(len(key)) >= n.prefixLen && unsafe.String(n.prefixP, n.prefixLen) == string(key[:n.prefixLen])
}

func (n *header[T]) setPrefix(p []byte) {
	if len(p) > 0 {
		n.prefixP = &p[0]
	}
	n.prefixLen = uint16(len(p))
}

const kindMask = uint16(0b1111_000_00000000_0)

func (n *header[T]) kind() nodeKind {
	return nodeKind(n.flags >> 12)
}

func (n *header[T]) setKind(k nodeKind) {
	n.flags = (n.flags & ^kindMask) | (uint16(k&0b1111) << 12)
}

const sizeMask = uint16(0b0000_000_1111_1111_1)

func (n *header[T]) cap() int {
	switch n.kind() {
	case nodeKindLeaf:
		return 0
	case nodeKind4:
		return 4
	case nodeKind16:
		return 16
	case nodeKind48:
		return 48
	case nodeKind256:
		return 256
	default:
		panic(fmt.Sprintf("unknown node kind: %x", n.kind()))
	}
}

func (n *header[T]) isLeaf() bool {
	return n.kind() == nodeKindLeaf
}

func (n *header[T]) getLeaf() *leaf[T] {
	switch n.kind() {
	case nodeKindLeaf:
		return (*leaf[T])(unsafe.Pointer(n))
	case nodeKind4:
		return n.node4().leaf
	case nodeKind16:
		return n.node16().leaf
	case nodeKind48:
		return n.node48().leaf
	case nodeKind256:
		return n.node256().leaf
	default:
		panic(fmt.Sprintf("unknown node kind: %x", n.kind()))
	}
}

func (n *header[T]) setLeaf(l *leaf[T]) {
	switch n.kind() {
	case nodeKindLeaf:
		panic("cannot setLeaf on a leaf[T]")
	case nodeKind4:
		n.node4().leaf = l
	case nodeKind16:
		n.node16().leaf = l
	case nodeKind48:
		n.node48().leaf = l
	case nodeKind256:
		n.node256().leaf = l
	default:
		panic(fmt.Sprintf("unknown node kind: %x", n.kind()))
	}
}

func (n *header[T]) size() int {
	return int(n.flags & sizeMask)
}

func (n *header[T]) setSize(size int) {
	n.flags = (n.flags & ^sizeMask) | uint16(size)&sizeMask
}

func (n *header[T]) self() *header[T] {
	return n
}

func (n *header[T]) node4() *node4[T] {
	return (*node4[T])(unsafe.Pointer(n))
}

func (n *header[T]) node16() *node16[T] {
	return (*node16[T])(unsafe.Pointer(n))
}

func (n *header[T]) node48() *node48[T] {
	return (*node48[T])(unsafe.Pointer(n))
}

func (n *header[T]) node256() *node256[T] {
	return (*node256[T])(unsafe.Pointer(n))
}

func (n *header[T]) txnID() uint64 {
	switch n.kind() {
	case nodeKindLeaf:
		return 0
	case nodeKind4:
		return n.node4().txnID
	case nodeKind16:
		return n.node16().txnID
	case nodeKind48:
		return n.node48().txnID
	case nodeKind256:
		return n.node256().txnID
	default:
		panic(fmt.Sprintf("unknown node kind: %x", n.kind()))
	}
}

func (n *header[T]) setTxnID(txnID uint64) {
	switch n.kind() {
	case nodeKindLeaf:
		return
	case nodeKind4:
		n.node4().txnID = txnID
	case nodeKind16:
		n.node16().txnID = txnID
	case nodeKind48:
		n.node48().txnID = txnID
	case nodeKind256:
		n.node256().txnID = txnID
	default:
		panic(fmt.Sprintf("unknown node kind: %x", n.kind()))
	}
}

// clone returns a shallow clone of the node.
// We are working on the assumption here that only
// value-types are mutated in the returned clone.
func (n *header[T]) clone(watch bool) *header[T] {
	var nCopy *header[T]
	switch n.kind() {
	case nodeKindLeaf:
		l := *n.getLeaf()
		nCopy = (&l).self()
	case nodeKind4:
		n4 := *n.node4()
		nCopy = (&n4).self()
	case nodeKind16:
		n16 := *n.node16()
		nCopy = (&n16).self()
	case nodeKind48:
		n48 := *n.node48()
		nCopy = (&n48).self()
	case nodeKind256:
		nCopy256 := *n.node256()
		nCopy = (&nCopy256).self()
	default:
		panic(fmt.Sprintf("unknown node kind: %x", n.kind()))
	}
	if watch {
		nCopy.watch = make(chan struct{})
	} else {
		nCopy.watch = nil
	}
	return nCopy
}

func (n *header[T]) promote(txnID uint64) *header[T] {
	switch n.kind() {
	case nodeKindLeaf:
		node4 := &node4[T]{}
		node4.prefixLen = n.prefixLen
		node4.prefixP = n.prefixP
		node4.leaf = n.getLeaf()
		node4.txnID = txnID
		node4.setKind(nodeKind4)
		if n.watch != nil {
			node4.watch = make(chan struct{})
		}
		return node4.self()
	case nodeKind4:
		node4 := n.node4()
		node16 := &node16[T]{header: *n}
		node16.txnID = txnID
		node16.setKind(nodeKind16)
		node16.leaf = n.getLeaf()
		size := node4.size()
		copy(node16.children[:], node4.children[:size])
		copy(node16.keys[:], node4.keys[:size])
		if n.watch != nil {
			node16.watch = make(chan struct{})
		}
		return node16.self()
	case nodeKind16:
		node16 := n.node16()
		node48 := &node48[T]{header: *n}
		node48.txnID = txnID
		node48.setKind(nodeKind48)
		node48.leaf = n.getLeaf()
		copy(node48.children[:], node16.children[:node16.size()])
		for i, k := range node16.keys[:node16.size()] {
			node48.index[k] = uint8(i + 1)
		}
		if n.watch != nil {
			node48.watch = make(chan struct{})
		}
		return node48.self()
	case nodeKind48:
		node48 := n.node48()
		node256 := &node256[T]{header: *n}
		node256.txnID = txnID
		node256.setKind(nodeKind256)
		node256.leaf = n.getLeaf()

		// Since Node256 has children indexed directly, iterate over the children
		// to assign them to the right index.
		for _, child := range node48.children[:node48.size()] {
			node256.children[child.prefix()[0]] = child
		}
		if n.watch != nil {
			node256.watch = make(chan struct{})
		}
		return node256.self()
	case nodeKind256:
		panic("BUG: should not need to promote node256")
	default:
		panic(fmt.Sprintf("unknown node kind: %x", n.kind()))
	}
}

func isClosedChan(ch <-chan struct{}) bool {
	select {
	case <-ch:
		return true
	default:
		return false
	}
}

func (n *header[T]) printTree(level int) {
	if n == nil {
		return
	}
	fmt.Print(strings.Repeat(" ", level))

	var children []*header[T]
	switch n.kind() {
	case nodeKindLeaf:
		fmt.Printf("leaf[%x]:", n.prefix())
	case nodeKind4:
		fmt.Printf("node4[%x]:", n.prefix())
		children = n.node4().children[:n.size()]
	case nodeKind16:
		fmt.Printf("node16[%x]:", n.prefix())
		children = n.node16().children[:n.size()]
	case nodeKind48:
		fmt.Printf("node48[%x]:", n.prefix())
		children = n.node48().children[:n.size()]
	case nodeKind256:
		fmt.Printf("node256[%x]:", n.prefix())
		children = n.node256().children[:]
	default:
		panic("unknown node kind")
	}
	if leaf := n.getLeaf(); leaf != nil {
		fmt.Printf(" %x -> %v (L:%p W:%p %v)", leaf.fullKey(), leaf.value, leaf, leaf.watch, isClosedChan(leaf.watch))
	}
	fmt.Printf(" (N:%p, W:%p %v)\n", n, n.watch, isClosedChan(n.watch))

	for _, child := range children {
		if child != nil {
			child.printTree(level + 1)
		}
	}
}

func (n *header[T]) children() []*header[T] {
	switch n.kind() {
	case nodeKindLeaf:
		return nil
	case nodeKind4:
		return n.node4().children[0:n.size():4]
	case nodeKind16:
		return n.node16().children[0:n.size():16]
	case nodeKind48:
		return n.node48().children[0:n.size():48]
	case nodeKind256:
		return n.node256().children[:]
	default:
		panic(fmt.Sprintf("unknown node kind: %x", n.kind()))
	}
}

func (n *header[T]) findIndex(key byte) (*header[T], int) {
	switch n.kind() {
	case nodeKindLeaf:
		return nil, 0
	case nodeKind4:
		n4 := n.node4()
		size := n4.size()
		i := size
		switch {
		case n4.keys[0] >= key:
			i = 0
		case n4.keys[1] >= key:
			i = 1
		case n4.keys[2] >= key:
			i = 2
		case n4.keys[3] >= key:
			i = 3
		}
		if i < size && n4.keys[i] == key {
			return n4.children[i], i
		}
		return nil, i
	case nodeKind16:
		n16 := n.node16()
		size := n16.size()
		for i := 0; i < int(size); i++ {
			k := n16.keys[i]
			if k >= key {
				if k == key {
					return n16.children[i], i
				}
				return nil, i
			}
		}
		return nil, size
	case nodeKind48:
		n48 := n.node48()
		// Check for exact match first
		if idx := n48.index[key]; idx != 0 {
			i := int(idx - 1)
			return n48.children[i], i
		}
		// No exact match. Binary search to find insertion point.
		size := n48.size()
		children := n48.children[:size]
		// Is the key between smallest and highest?
		switch {
		case key < children[0].key():
			return nil, 0
		case key > children[size-1].key():
			return nil, size
		}
		// No exact match, but key is in range. Binary search to find insertion point.
		// We're not using sort.Search as that requires a function closure.
		lo, hi := 0, size
		for lo < hi {
			mid := int(uint(lo+hi) / 2)
			if children[mid].key() < key {
				lo = mid + 1
			} else {
				hi = mid
			}
		}
		return nil, lo
	case nodeKind256:
		return n.node256().children[key], int(key)
	default:
		panic(fmt.Sprintf("unknown node kind: %x", n.kind()))
	}
}

func (n *header[T]) find(key byte) *header[T] {
	switch n.kind() {
	case nodeKindLeaf:
		return nil
	case nodeKind4:
		n4 := n.node4()
		keys := n4.keys
		switch key {
		case keys[0]:
			return n4.children[0]
		case keys[1]:
			return n4.children[1]
		case keys[2]:
			return n4.children[2]
		case keys[3]:
			return n4.children[3]
		}
		return nil
	case nodeKind16:
		n16 := n.node16()
		if idx := bytes.IndexByte(n16.keys[:n16.size()], key); idx >= 0 {
			return n16.children[idx]
		}
		return nil
	case nodeKind48:
		n48 := n.node48()
		idx := n48.index[key]
		if idx == 0 {
			return nil
		}
		return n48.children[idx-1]
	case nodeKind256:
		return n.node256().children[key]
	default:
		panic(fmt.Sprintf("unknown node kind: %x", n.kind()))
	}
}

func (n *header[T]) insert(idx int, child *header[T]) {
	size := n.size()
	newSize := size + 1
	switch n.kind() {
	case nodeKind4:
		n4 := n.node4()
		// Shift to make room
		copy(n4.children[idx+1:newSize], n4.children[idx:newSize])
		copy(n4.keys[idx+1:newSize], n4.keys[idx:newSize])
		n4.children[idx] = child
		n4.keys[idx] = child.key()
	case nodeKind16:
		n16 := n.node16()
		// Shift to make room
		copy(n16.children[idx+1:newSize], n16.children[idx:newSize])
		copy(n16.keys[idx+1:newSize], n16.keys[idx:newSize])
		n16.children[idx] = child
		n16.keys[idx] = child.key()
	case nodeKind48:
		// Shift to make room
		n48 := n.node48()
		for i := size - 1; i >= idx; i-- {
			c := n48.children[i]
			n48.index[c.key()] = uint8(i + 2)
			n48.children[i+1] = c
		}
		n48.children[idx] = child
		n48.index[child.key()] = uint8(idx + 1)
	case nodeKind256:
		n.node256().children[child.key()] = child
	default:
		panic(fmt.Sprintf("unknown node kind: %x", n.kind()))
	}
	n.setSize(size + 1)
}

func (n *header[T]) remove(idx int) {
	newSize := n.size() - 1
	switch n.kind() {
	case nodeKind4:
		size := n.size()
		n4 := n.node4()
		copy(n4.keys[idx:size], n4.keys[idx+1:size])
		copy(n4.children[idx:size], n4.children[idx+1:size])
		n4.children[newSize] = nil
		n4.keys[newSize] = 255
	case nodeKind16:
		size := n.size()
		n16 := n.node16()
		copy(n16.keys[idx:size], n16.keys[idx+1:size])
		copy(n16.children[idx:size], n16.children[idx+1:size])
		n16.children[newSize] = nil
		n16.keys[newSize] = 255
	case nodeKind48:
		children := n.children()
		key := children[idx].key()
		n48 := n.node48()
		for i := idx; i < newSize; i++ {
			child := children[i+1]
			children[i] = child
			n48.index[child.key()] = uint8(i + 1)
		}
		n48.index[key] = 0
		children[newSize] = nil
	case nodeKind256:
		n.node256().children[idx] = nil
	default:
		panic(fmt.Sprintf("unknown node kind: %x", n.kind()))
	}
	n.setSize(newSize)
}

type leaf[T any] struct {
	header[T]
	value  T
	keyLen uint16
	keyP   *byte // the full key
}

func (l *leaf[T]) fullKey() []byte {
	return unsafe.Slice(l.keyP, l.keyLen)
}

func newLeaf[T any](o options, prefix, key []byte, value T) *leaf[T] {
	var keyP *byte
	if len(key) > 0 {
		keyP = &key[0]
	}
	leaf := &leaf[T]{keyLen: uint16(len(key)), keyP: keyP, value: value}
	leaf.setPrefix(prefix)
	leaf.setKind(nodeKindLeaf)
	if !o.rootOnlyWatch() {
		leaf.watch = make(chan struct{})
	}

	return leaf
}

type node4[T any] struct {
	header[T]
	txnID    uint64   // transaction ID that last mutated this node
	leaf     *leaf[T] // non-nil if this node contains a value
	children [4]*header[T]
	keys     [4]byte
}

type node16[T any] struct {
	header[T]
	txnID    uint64   // transaction ID that last mutated this node
	leaf     *leaf[T] // non-nil if this node contains a value
	children [16]*header[T]
	keys     [16]byte
}

type node48[T any] struct {
	header[T]
	txnID    uint64 // transaction ID that last mutated this node
	children [48]*header[T]
	leaf     *leaf[T]   // non-nil if this node contains a value
	index    [256]uint8 // 1-based index for key in [children] (0 is absent, 1 is children[0])
}

type node256[T any] struct {
	header[T]
	txnID    uint64   // transaction ID that last mutated this node
	leaf     *leaf[T] // non-nil if this node contains a value
	children [256]*header[T]
}

func search[T any](root *header[T], rootWatch <-chan struct{}, key []byte) (value T, watch <-chan struct{}, ok bool) {
	this := root
	watch = rootWatch
	if root == nil {
		return
	}
	for {
		if !this.isPrefixOf(key) {
			return
		}

		// Consume the prefix
		key = key[this.prefixLen:]

		if len(key) == 0 {
			if leaf := this.getLeaf(); leaf != nil {
				value = leaf.value
				if leaf.watch != nil {
					watch = leaf.watch
				}
				ok = true
			}
			return
		}

		// Prefix matched. Remember this as the closest watch channel as we traverse
		// further.
		if this.watch != nil && !this.isLeaf() {
			watch = this.watch
		}

		this = this.find(key[0])
		if this == nil {
			return
		}
	}
}

func commonPrefix(a, b []byte) []byte {
	n := min(len(a), len(b))
	for i := range n {
		if a[i] != b[i] {
			return a[:i]
		}
	}
	return a[:n]
}
