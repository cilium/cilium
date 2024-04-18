package part

import "unsafe"

const nodeMutatedSize = 32 // must be power-of-two

type nodeMutated[T any] struct {
	ptrs [nodeMutatedSize]*header[T]
	used bool
}

func (p *nodeMutated[T]) put(ptr *header[T]) {
	ptrInt := uintptr(unsafe.Pointer(ptr))
	p.ptrs[slot(ptrInt)] = ptr
	p.used = true
}

func (p *nodeMutated[T]) exists(ptr *header[T]) bool {
	ptrInt := uintptr(unsafe.Pointer(ptr))
	return p.ptrs[slot(ptrInt)] == ptr
}

func slot(p uintptr) int {
	var slot uint8
	// use some relevant bits from the pointer
	slot = slot + uint8(p>>4)
	slot = slot + uint8(p>>12)
	slot = slot + uint8(p>>20)
	return int(slot & (nodeMutatedSize - 1))
}

func (p *nodeMutated[T]) clear() {
	if p.used {
		clear(p.ptrs[:])
	}
	p.used = false
}
