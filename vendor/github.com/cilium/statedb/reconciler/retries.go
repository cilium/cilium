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
	queue := newRetryPrioQueue(
		func(items []*retryItem, i, j int) bool {
			return items[i].retryAt.Before(items[j].retryAt)
		},
		func(item *retryItem, idx int) {
			item.index = idx
		},
	)
	revQueue := newRetryPrioQueue(
		func(items []*retryItem, i, j int) bool {
			return items[i].origRev < items[j].origRev
		},
		func(item *retryItem, idx int) {
			item.revIndex = idx
		},
	)
	return &retries{
		backoff: exponentialBackoff{
			min: minDuration,
			max: maxDuration,
		},
		queue:       queue,
		revQueue:    revQueue,
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
	backoff exponentialBackoff

	// queue stores items to be retried by their 'retryAt' time
	queue *retryPrioQueue

	// revQueue stores items by their original revision. Used to compute the
	// low watermark revision in order to implement [WaitUntilReconciled].
	revQueue *retryPrioQueue

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
	object  any // the object that is being retried. 'any' to avoid specializing this internal code.
	rev     statedb.Revision
	origRev statedb.Revision
	delete  bool

	index      int       // item's index in the retry time priority queue
	revIndex   int       // item's index in the revision priority queue
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
	return rq.queue.Peek(), true
}

func (rq *retries) Pop() {
	// Pop the object from the queue, but leave it into the map until
	// the object is cleared or re-added.
	rq.queue.PopItem()

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
			d := time.Until(rq.queue.Peek().retryAt)
			rq.waitTimer = time.AfterFunc(d, func() { close(waitChan) })
		}
	} else if rq.queue.Len() > 0 {
		d := time.Until(rq.queue.Peek().retryAt)
		// Did not fire yet so we can just reset the timer.
		rq.waitTimer.Reset(d)
	}
}

func (rq *retries) Add(obj any, rev statedb.Revision, origRev statedb.Revision, delete bool, lastError error) {
	var (
		item *retryItem
		ok   bool
	)
	key := rq.objectToKey(obj)
	keyStr := string(key)
	if item, ok = rq.items[keyStr]; !ok {
		item = &retryItem{
			numRetries: 0,
			index:      -1,
			revIndex:   -1,
		}
		rq.items[keyStr] = item
	}
	item.object = obj
	item.rev = rev
	item.origRev = origRev
	item.delete = delete
	item.numRetries += 1
	item.lastError = lastError
	duration := rq.backoff.Duration(item.numRetries)
	item.retryAt = time.Now().Add(duration)

	// Add the item into the revision key'd priority queue
	if item.revIndex >= 0 {
		rq.revQueue.Fix(item.revIndex)
	} else {
		rq.revQueue.PushItem(item)
	}

	// Add the item into the retryAt key'd priority queue
	if item.index >= 0 {
		// The item was already in the queue, fix up its position.
		rq.queue.Fix(item.index)
	} else {
		rq.queue.PushItem(item)
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
		if item.index >= 0 && item.index < len(rq.queue.items) &&
			key.Equal(rq.objectToKey(rq.queue.items[item.index].object)) {
			rq.queue.Remove(item.index)

			// Reset the timer in case we removed the top item.
			if index == 0 {
				rq.resetTimer()
			}
		}
		if item.revIndex >= 0 && item.revIndex < len(rq.revQueue.items) &&
			key.Equal(rq.objectToKey(rq.revQueue.items[item.revIndex].object)) {
			rq.revQueue.Remove(item.revIndex)
		}
		// Completely forget the object and its retry count.
		delete(rq.items, string(key))
	}
}

func (rq *retries) LowWatermark() statedb.Revision {
	for rq.revQueue.Len() > 0 {
		top := rq.revQueue.Peek()
		key := rq.objectToKey(top.object)
		if item, ok := rq.items[string(key)]; ok && item == top {
			return top.origRev
		}
		rq.revQueue.PopItem()
	}
	return 0
}

type retryPrioQueue struct {
	items    []*retryItem
	less     func(items []*retryItem, i, j int) bool
	setIndex func(*retryItem, int)
}

func newRetryPrioQueue(
	less func(items []*retryItem, i, j int) bool,
	setIndex func(*retryItem, int),
) *retryPrioQueue {
	return &retryPrioQueue{
		less:     less,
		setIndex: setIndex,
	}
}

func (hq *retryPrioQueue) Len() int { return len(hq.items) }

func (hq *retryPrioQueue) Less(i, j int) bool { return hq.less(hq.items, i, j) }

func (hq *retryPrioQueue) Swap(i, j int) {
	hq.items[i], hq.items[j] = hq.items[j], hq.items[i]
	hq.setIndex(hq.items[i], i)
	hq.setIndex(hq.items[j], j)
}

func (hq *retryPrioQueue) Push(x any) {
	item := x.(*retryItem)
	hq.setIndex(item, len(hq.items))
	hq.items = append(hq.items, item)
}

func (hq *retryPrioQueue) Pop() any {
	n := len(hq.items)
	item := hq.items[n-1]
	hq.items[n-1] = nil // avoid memory leak
	hq.setIndex(item, -1)
	hq.items = hq.items[:n-1]
	return item
}

func (hq *retryPrioQueue) Peek() *retryItem {
	return hq.items[0]
}

func (hq *retryPrioQueue) PushItem(item *retryItem) {
	heap.Push(hq, item)
}

func (hq *retryPrioQueue) PopItem() *retryItem {
	return heap.Pop(hq).(*retryItem)
}

func (hq *retryPrioQueue) Fix(index int) {
	heap.Fix(hq, index)
}

func (hq *retryPrioQueue) Remove(index int) {
	heap.Remove(hq, index)
}
