// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package part

import (
	"unsafe"
)

const nodeMutatedSize = 256 // must be power-of-two

// nodeMutated is a probabilistic check for seeing if a node has
// been cloned within a transaction and thus can be modified in-place
// since it has not been seen outside. This significantly speeds up
// writes within a single write transaction as inner nodes no longer
// need to be cloned on every change, effectively making the immutable
// radix tree perform as if it's a mutable one.
//
// Earlier versions of StateDB just used a map[*header[T]]struct{}, but
// that was fairly costly and experiments showed that it's enough to most
// of the time avoid the clone to perform well.
//
// The value for [nodeMutatedSize] is a balance between making Txn()
// not too costly (due to e.g. clear()) and between giving a high likelyhood
// that we mutate nodes in-place.
type nodeMutated[T any] struct {
	ptrs [nodeMutatedSize]*header[T]
	used bool
}

func (nm *nodeMutated[T]) set(n *header[T]) {
	if nm == nil {
		return
	}
	ptrInt := uintptr(unsafe.Pointer(n))
	nm.ptrs[slot(ptrInt)] = n
	nm.used = true
}

func (nm *nodeMutated[T]) exists(n *header[T]) bool {
	if nm == nil {
		return false
	}
	ptrInt := uintptr(unsafe.Pointer(n))
	return nm.ptrs[slot(ptrInt)] == n
}

// slot returns the index in the [ptrs] array for a given pointer.
// The Go spec allows objects to be moved so it may be that the same
// instance of an object is assigned to a different memory location in
// which case we'd no longer report that node as being in the cache.
// This is fine though as we do compare the actual *header[T] pointers
// and this is probabilistic anyway as this is a fixed size cache.
func slot(p uintptr) int {
	p >>= 4 // ignore low order bits
	// use some relevant bits from the pointer
	slot := uint8(p) ^ uint8(p>>8) ^ uint8(p>>16)
	return int(slot & (nodeMutatedSize - 1))
}

func (nm *nodeMutated[T]) clear() {
	if nm == nil {
		return
	}
	if nm.used {
		clear(nm.ptrs[:])
	}
	nm.used = false
}
