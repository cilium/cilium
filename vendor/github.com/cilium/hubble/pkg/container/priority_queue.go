// Copyright 2020 Authors of Hubble
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

package container

import (
	"container/heap"

	"github.com/cilium/hubble/pkg/api/v1"
)

// PriorityQueue is a priority queue of events that implements heap.Interface.
// Events are ordered based on their timestamp value, the oldest event having
// the higher priority.
//
// This implementation is loosely based on the priority queue example in
// "container/heap".
type PriorityQueue struct {
	h minHeap
}

type minHeap []*v1.Event

// Ensure that minHeap implements heap.Interface.
var _ heap.Interface = (*minHeap)(nil)

// NewPriorityQueue creates a new PriorityQueue with initial capacity n.
func NewPriorityQueue(n int) *PriorityQueue {
	h := make(minHeap, 0, n)
	heap.Init(&h)
	return &PriorityQueue{h}
}

// Len is the number of events in the queue.
func (pq PriorityQueue) Len() int {
	return pq.h.Len()
}

// Push adds event e to the queue.
func (pq *PriorityQueue) Push(e *v1.Event) {
	heap.Push(&pq.h, e)
}

// Pop removes and returns the oldest event in the queue. Pop returns nil if
// the queue is empty.
func (pq *PriorityQueue) Pop() *v1.Event {
	event := heap.Pop(&pq.h).(*v1.Event)
	return event
}

func (h minHeap) Len() int {
	return len(h)
}

func (h minHeap) Less(i, j int) bool {
	if h[i].Timestamp.GetSeconds() == h[j].Timestamp.GetSeconds() {
		return h[i].Timestamp.GetNanos() < h[j].Timestamp.GetNanos()
	}
	return h[i].Timestamp.GetSeconds() < h[j].Timestamp.GetSeconds()
}

func (h minHeap) Swap(i, j int) {
	n := len(h)
	if (i >= 0 && i <= n-1) && (j >= 0 && j <= n-1) {
		h[i], h[j] = h[j], h[i]
	}
}

func (h *minHeap) Push(x interface{}) {
	event := x.(*v1.Event)
	*h = append(*h, event)
}

func (h *minHeap) Pop() interface{} {
	old := *h
	n := len(old)
	if n == 0 {
		return (*v1.Event)(nil)
	}
	event := old[n-1]
	old[n-1] = nil // avoid memory leak
	*h = old[0 : n-1]
	return event
}
