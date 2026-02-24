// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package part

import (
	"unsafe"
)

const nodeMutatedSize = 256 // must be power-of-two

type nodeMutated struct {
	ptrs [nodeMutatedSize]uintptr
	used bool
}

func nodeMutatedSet[T any](nm *nodeMutated, ptr *header[T]) {
	if nm == nil {
		return
	}
	ptrInt := uintptr(unsafe.Pointer(ptr))
	nm.ptrs[slot(ptrInt)] = ptrInt
	nm.used = true
}

func nodeMutatedExists[T any](nm *nodeMutated, ptr *header[T]) bool {
	if nm == nil {
		return false
	}
	ptrInt := uintptr(unsafe.Pointer(ptr))
	return nm.ptrs[slot(ptrInt)] == ptrInt
}

func slot(p uintptr) int {
	p >>= 4 // ignore low order bits
	// use some relevant bits from the pointer
	slot := uint8(p) ^ uint8(p>>8) ^ uint8(p>>16)
	return int(slot & (nodeMutatedSize - 1))
}

func (nm *nodeMutated) clear() {
	if nm == nil {
		return
	}
	if nm.used {
		clear(nm.ptrs[:])
	}
	nm.used = false
}
