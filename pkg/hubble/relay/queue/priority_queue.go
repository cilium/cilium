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

package queue

import (
	"container/heap"
	"time"

	observerpb "github.com/cilium/cilium/api/v1/observer"
)

// PriorityQueue is a priority queue of observerpb.GetFlowsResponse. It
// implements heap.Interface. GetFlowsResponse objects are ordered based on
// their timestamp value; the older the timestamp, the higher the priority.
//
// This implementation is loosely based on the priority queue example in
// "container/heap".
type PriorityQueue struct {
	h minHeap
}

type minHeap []*observerpb.GetFlowsResponse

// Ensure that minHeap implements heap.Interface.
var _ heap.Interface = (*minHeap)(nil)

// NewPriorityQueue creates a new PriorityQueue with initial capacity n.
func NewPriorityQueue(n int) *PriorityQueue {
	h := make(minHeap, 0, n)
	heap.Init(&h)
	return &PriorityQueue{h}
}

// Len is the number of objects in the queue.
func (pq PriorityQueue) Len() int {
	return pq.h.Len()
}

// Push adds object resp to the queue.
func (pq *PriorityQueue) Push(resp *observerpb.GetFlowsResponse) {
	heap.Push(&pq.h, resp)
}

// Pop removes and returns the oldest object in the queue. Pop returns nil when
// the queue is empty.
func (pq *PriorityQueue) Pop() *observerpb.GetFlowsResponse {
	resp := heap.Pop(&pq.h).(*observerpb.GetFlowsResponse)
	return resp
}

// PopOlderThan removes and returns objects in the queue that are older than t.
// Objects in the returned list are sorted chronologically from the oldest to
// the more recent.
func (pq *PriorityQueue) PopOlderThan(t time.Time) []*observerpb.GetFlowsResponse {
	// pre-allocate enough memory for the slice to hold every element in the
	// queue as flushing the entire queue is a common pattern
	ret := make([]*observerpb.GetFlowsResponse, 0, pq.Len())
	for {
		resp := pq.Pop()
		if resp == nil {
			return ret
		}
		if t.Before(resp.GetTime().AsTime()) {
			pq.Push(resp)
			return ret
		}
		ret = append(ret, resp)
	}
}

func (h minHeap) Len() int {
	return len(h)
}

func (h minHeap) Less(i, j int) bool {
	if h[i].GetTime().GetSeconds() == h[j].GetTime().GetSeconds() {
		return h[i].GetTime().GetNanos() < h[j].GetTime().GetNanos()
	}
	return h[i].GetTime().GetSeconds() < h[j].GetTime().GetSeconds()
}

func (h minHeap) Swap(i, j int) {
	n := len(h)
	if (i >= 0 && i <= n-1) && (j >= 0 && j <= n-1) {
		h[i], h[j] = h[j], h[i]
	}
}

func (h *minHeap) Push(x interface{}) {
	resp := x.(*observerpb.GetFlowsResponse)
	*h = append(*h, resp)
}

func (h *minHeap) Pop() interface{} {
	old := *h
	n := len(old)
	if n == 0 {
		return (*observerpb.GetFlowsResponse)(nil)
	}
	resp := old[n-1]
	old[n-1] = nil // avoid memory leak
	*h = old[0 : n-1]
	return resp
}
