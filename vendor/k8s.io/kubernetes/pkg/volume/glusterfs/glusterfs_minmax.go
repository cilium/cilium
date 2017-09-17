/*
Copyright 2016 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

//
// This implementation is space-efficient for a sparse
// allocation over a big range. Could be optimized
// for high absolute allocation number with a bitmap.
//

package glusterfs

import (
	"errors"
	"sync"
)

var (
	//ErrConflict returned when value is already in use.
	ErrConflict = errors.New("number already allocated")

	//ErrInvalidRange returned invalid range, for eg# min > max
	ErrInvalidRange = errors.New("invalid range")

	//ErrOutOfRange returned when value is not in pool range.
	ErrOutOfRange = errors.New("out of range")

	//ErrRangeFull returned when no more free values in the pool.
	ErrRangeFull = errors.New("range full")

	//ErrInternal returned when no free item found, but a.free != 0.
	ErrInternal = errors.New("internal error")
)

//MinMaxAllocator defines allocator struct.
type MinMaxAllocator struct {
	lock sync.Mutex
	min  int
	max  int
	free int
	used map[int]bool
}

var _ Rangeable = &MinMaxAllocator{}

// Rangeable is an Interface that can adjust its min/max range.
// Rangeable should be threadsafe
type Rangeable interface {
	Allocate(int) (bool, error)
	AllocateNext() (int, bool, error)
	Release(int) error
	Has(int) bool
	Free() int
	SetRange(min, max int) error
}

// NewMinMaxAllocator return a new allocator or error based on provided min/max value.
func NewMinMaxAllocator(min, max int) (*MinMaxAllocator, error) {
	if min > max {
		return nil, ErrInvalidRange
	}
	return &MinMaxAllocator{
		min:  min,
		max:  max,
		free: 1 + max - min,
		used: map[int]bool{},
	}, nil
}

//SetRange defines the range/pool with provided min and max values.
func (a *MinMaxAllocator) SetRange(min, max int) error {
	if min > max {
		return ErrInvalidRange
	}

	a.lock.Lock()
	defer a.lock.Unlock()

	// Check if we need to change
	if a.min == min && a.max == max {
		return nil
	}

	a.min = min
	a.max = max

	// Recompute how many free we have in the range
	numUsed := 0
	for i := range a.used {
		if a.inRange(i) {
			numUsed++
		}
	}
	a.free = 1 + max - min - numUsed

	return nil
}

//Allocate allocates provided value in the allocator and mark it as used.
func (a *MinMaxAllocator) Allocate(i int) (bool, error) {
	a.lock.Lock()
	defer a.lock.Unlock()

	if !a.inRange(i) {
		return false, ErrOutOfRange
	}

	if a.has(i) {
		return false, ErrConflict
	}

	a.used[i] = true
	a.free--

	return true, nil
}

//AllocateNext allocates next value from the allocator.
func (a *MinMaxAllocator) AllocateNext() (int, bool, error) {
	a.lock.Lock()
	defer a.lock.Unlock()

	// Fast check if we're out of items
	if a.free <= 0 {
		return 0, false, ErrRangeFull
	}

	// Scan from the minimum until we find a free item
	for i := a.min; i <= a.max; i++ {
		if !a.has(i) {
			a.used[i] = true
			a.free--
			return i, true, nil
		}
	}

	// no free item found, but a.free != 0
	return 0, false, ErrInternal
}

//Release free/delete provided value from the allocator.
func (a *MinMaxAllocator) Release(i int) error {
	a.lock.Lock()
	defer a.lock.Unlock()

	if !a.has(i) {
		return nil
	}

	delete(a.used, i)

	if a.inRange(i) {
		a.free++
	}

	return nil
}

func (a *MinMaxAllocator) has(i int) bool {
	_, ok := a.used[i]
	return ok
}

//Has check whether the provided value is used in the allocator
func (a *MinMaxAllocator) Has(i int) bool {
	a.lock.Lock()
	defer a.lock.Unlock()

	return a.has(i)
}

//Free returns the number of free values in the allocator.
func (a *MinMaxAllocator) Free() int {
	a.lock.Lock()
	defer a.lock.Unlock()
	return a.free
}

func (a *MinMaxAllocator) inRange(i int) bool {
	return a.min <= i && i <= a.max
}
