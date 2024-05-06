// Copyright 2017 Google Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package pq provides a priority queue.
package pq

import "container/heap"

// NewQueue returns an unbounded priority queue that compares elements using
// less; the minimal element is at the top of the queue.
//
// If setIndex is not nil, the queue calls setIndex to inform each element of
// its position in the queue.  If an element's priority changes, its position in
// the queue may be incorrect.  Call Fix on the element's index to update the
// queue.  Call Remove on the element's index to remove it from the queue.
func NewQueue(less func(x, y interface{}) bool, setIndex func(x interface{}, idx int)) *Queue {
	return &Queue{
		heap: pqHeap{
			less:     less,
			setIndex: setIndex,
		},
	}
}

// Queue is a priority queue that supports updating the priority of an element.
// A Queue must be created with NewQueue.
type Queue struct {
	heap pqHeap
}

// Len returns the number of elements in the queue.
func (pq *Queue) Len() int {
	return pq.heap.Len()
}

// Push adds x to the queue.
func (pq *Queue) Push(x interface{}) {
	heap.Push(&pq.heap, x)
}

// Min returns the minimal element.
// Min panics if the queue is empty.
func (pq *Queue) Min() interface{} {
	return pq.heap.a[0]
}

// Pop removes and returns the minimal element.
// Pop panics if the queue is empty.
func (pq *Queue) Pop() interface{} {
	return heap.Pop(&pq.heap)
}

// Fix adjusts the heap to reflect that the element at index has changed priority.
func (pq *Queue) Fix(index int) {
	heap.Fix(&pq.heap, index)
}

// Remove removes the element at index i from the heap.
func (pq *Queue) Remove(index int) {
	heap.Remove(&pq.heap, index)
}

// pqHeap implements heap.Interface.
type pqHeap struct {
	a        []interface{}
	less     func(x, y interface{}) bool
	setIndex func(x interface{}, idx int)
}

func (h pqHeap) Len() int {
	return len(h.a)
}

func (h pqHeap) Less(i, j int) bool {
	return h.less(h.a[i], h.a[j])
}

func (h pqHeap) Swap(i, j int) {
	h.a[i], h.a[j] = h.a[j], h.a[i]
	if h.setIndex != nil {
		h.setIndex(h.a[i], i)
		h.setIndex(h.a[j], j)
	}
}

func (h *pqHeap) Push(x interface{}) {
	n := len(h.a)
	if h.setIndex != nil {
		h.setIndex(x, n)
	}
	h.a = append(h.a, x)
}

func (h *pqHeap) Pop() interface{} {
	old := h.a
	n := len(old)
	x := old[n-1]
	h.a = old[:n-1]
	return x
}
