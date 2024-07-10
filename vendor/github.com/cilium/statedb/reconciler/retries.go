// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package reconciler

import (
	"container/heap"
	"math"
	"time"

	"github.com/cilium/statedb"
	"github.com/cilium/statedb/index"
)

type exponentialBackoff struct {
	min time.Duration
	max time.Duration
}

func (e *exponentialBackoff) Duration(attempt int) time.Duration {
	dur := float64(e.min) * math.Pow(2, float64(attempt))
	if dur > float64(e.max) {
		return e.max
	}
	return time.Duration(dur)
}

func newRetries(minDuration, maxDuration time.Duration, objectToKey func(any) index.Key) *retries {
	return &retries{
		backoff: exponentialBackoff{
			min: minDuration,
			max: maxDuration,
		},
		queue:       nil,
		items:       make(map[string]*retryItem),
		objectToKey: objectToKey,
		waitTimer:   nil,
		waitChan:    make(chan struct{}),
	}
}

// retries holds the items that failed to be reconciled in
// a priority queue ordered by retry time. Methods of 'retries'
// are not safe to access concurrently.
type retries struct {
	backoff     exponentialBackoff
	queue       retryPrioQueue
	items       map[string]*retryItem
	objectToKey func(any) index.Key
	waitTimer   *time.Timer
	waitChan    chan struct{}
}

func (rq *retries) errors() []error {
	errs := make([]error, 0, len(rq.items))
	for _, item := range rq.items {
		errs = append(errs, item.lastError)
	}
	return errs
}

type retryItem struct {
	object any // the object that is being retried. 'any' to avoid specializing this internal code.
	rev    statedb.Revision
	delete bool

	index      int       // item's index in the priority queue
	retryAt    time.Time // time at which to retry
	numRetries int       // number of retries attempted (for calculating backoff)
	lastError  error
}

// Wait returns a channel that is closed when there is an item to retry.
// Returns nil channel if no items are queued.
func (rq *retries) Wait() <-chan struct{} {
	return rq.waitChan
}

func (rq *retries) Top() (*retryItem, bool) {
	if rq.queue.Len() == 0 {
		return nil, false
	}
	return rq.queue[0], true
}

func (rq *retries) Pop() {
	// Pop the object from the queue, but leave it into the map until
	// the object is cleared or re-added.
	rq.queue[0].index = -1
	heap.Pop(&rq.queue)

	rq.resetTimer()
}

func (rq *retries) resetTimer() {
	if rq.waitTimer == nil || !rq.waitTimer.Stop() {
		// Already fired so the channel was closed. Create a new one
		// channel and timer.
		waitChan := make(chan struct{})
		rq.waitChan = waitChan
		if rq.queue.Len() == 0 {
			rq.waitTimer = nil
		} else {
			d := time.Until(rq.queue[0].retryAt)
			rq.waitTimer = time.AfterFunc(d, func() { close(waitChan) })
		}
	} else if rq.queue.Len() > 0 {
		d := time.Until(rq.queue[0].retryAt)
		// Did not fire yet so we can just reset the timer.
		rq.waitTimer.Reset(d)
	}
}

func (rq *retries) Add(obj any, rev statedb.Revision, delete bool, lastError error) {
	var (
		item *retryItem
		ok   bool
	)
	key := rq.objectToKey(obj)
	if item, ok = rq.items[string(key)]; !ok {
		item = &retryItem{
			numRetries: 0,
			index:      -1,
		}
		rq.items[string(key)] = item
	}
	item.object = obj
	item.rev = rev
	item.delete = delete
	item.numRetries += 1
	item.lastError = lastError
	duration := rq.backoff.Duration(item.numRetries)
	item.retryAt = time.Now().Add(duration)

	if item.index >= 0 {
		// The item was already in the queue, fix up its position.
		heap.Fix(&rq.queue, item.index)
	} else {
		heap.Push(&rq.queue, item)
	}

	// Item is at the head of the queue, reset the timer.
	if item.index == 0 {
		rq.resetTimer()
	}
}

func (rq *retries) Clear(obj any) {
	key := rq.objectToKey(obj)
	if item, ok := rq.items[string(key)]; ok {
		// Remove the object from the queue if it is still there.
		index := item.index // hold onto the index as heap.Remove messes with it
		if item.index >= 0 && item.index < len(rq.queue) &&
			key.Equal(rq.objectToKey(rq.queue[item.index].object)) {
			heap.Remove(&rq.queue, item.index)

			// Reset the timer in case we removed the top item.
			if index == 0 {
				rq.resetTimer()
			}
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
