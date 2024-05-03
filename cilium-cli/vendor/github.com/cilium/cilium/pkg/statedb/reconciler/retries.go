// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package reconciler

import (
	"container/heap"

	"github.com/cilium/cilium/pkg/backoff"
	"github.com/cilium/cilium/pkg/statedb/index"
	"github.com/cilium/cilium/pkg/time"
)

func newRetries(minDuration, maxDuration time.Duration, objectToKey func(any) index.Key) *retries {
	return &retries{
		backoff: backoff.Exponential{
			Min: minDuration,
			Max: maxDuration,
		},
		queue:       nil,
		items:       make(map[string]*retryItem),
		objectToKey: objectToKey,
	}
}

// retries holds the items that failed to be reconciled in
// a priority queue ordered by retry time. Methods of 'retries'
// are not safe to access concurrently.
type retries struct {
	backoff     backoff.Exponential
	queue       retryPrioQueue
	items       map[string]*retryItem
	objectToKey func(any) index.Key
}

type retryItem struct {
	object     any       // the object that is being retried. 'any' to avoid specializing this internal code.
	index      int       // item's index in the priority queue
	retryAt    time.Time // time at which to retry
	numRetries int       // number of retries attempted (for calculating backoff)
}

// Wait returns a channel that is closed when there is an item to retry.
// Returns nil channel if no items are queued.
func (rq *retries) Wait() <-chan struct{} {
	if _, retryAt, ok := rq.Top(); ok {
		now := time.Now()
		ch := make(chan struct{}, 1)
		if now.After(retryAt) {
			// Already expired.
			close(ch)
		} else {
			time.AfterFunc(retryAt.Sub(now), func() { close(ch) })
		}
		return ch
	}
	return nil
}

func (rq *retries) Top() (object any, retryAt time.Time, ok bool) {
	if rq.queue.Len() == 0 {
		return
	}
	item := rq.queue[0]
	return item.object, item.retryAt, true
}

func (rq *retries) Pop() {
	// Pop the object from the queue, but leave it into the map until
	// the object is cleared or re-added.
	heap.Pop(&rq.queue)
}

func (rq *retries) Add(obj any) {
	var (
		item *retryItem
		ok   bool
	)
	key := rq.objectToKey(obj)
	if item, ok = rq.items[string(key)]; !ok {
		item = &retryItem{
			numRetries: 0,
		}
		rq.items[string(key)] = item
	}
	item.object = obj
	item.numRetries += 1
	item.retryAt = time.Now().Add(rq.backoff.Duration(item.numRetries))
	heap.Push(&rq.queue, item)
}

func (rq *retries) Clear(obj any) {
	key := rq.objectToKey(obj)
	if item, ok := rq.items[string(key)]; ok {
		// Remove the object from the queue if it is still there.
		if item.index >= 0 && item.index < len(rq.queue) &&
			key.Equal(rq.objectToKey(rq.queue[item.index].object)) {
			heap.Remove(&rq.queue, item.index)
		}
		// Completely forget the object and its retry count.
		delete(rq.items, string(key))
	}
}

// retryPrioQueue is a slice-backed priority heap with the next
// expiring 'retryItem' at top. Implementation is adapted from the
// 'container/heap' PriorityQueue example.
type retryPrioQueue []*retryItem

func (pq retryPrioQueue) Len() int { return len(pq) }

func (pq retryPrioQueue) Less(i, j int) bool {
	return pq[i].retryAt.Before(pq[j].retryAt)
}

func (pq retryPrioQueue) Swap(i, j int) {
	pq[i], pq[j] = pq[j], pq[i]
	pq[i].index = i
	pq[j].index = j
}

func (pq *retryPrioQueue) Push(x any) {
	retryObj := x.(*retryItem)
	retryObj.index = len(*pq)
	*pq = append(*pq, retryObj)
}

func (pq *retryPrioQueue) Pop() any {
	old := *pq
	n := len(old)
	item := old[n-1]
	old[n-1] = nil  // avoid memory leak
	item.index = -1 // for safety
	*pq = old[0 : n-1]
	return item
}
