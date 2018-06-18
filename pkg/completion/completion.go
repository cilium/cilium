// Copyright 2018 Authors of Cilium
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

package completion

import (
	"context"

	"github.com/cilium/cilium/pkg/lock"
)

// WaitGroup waits for a collection of Completions to complete.
type WaitGroup struct {
	// ctx is the context of all the Completions in the wait group.
	ctx context.Context

	// counterLocker locks all calls to AddCompletion and Wait, which must not
	// be called concurrently.
	counterLocker lock.Mutex

	// pendingCompletions is the list of Completions returned by
	// AddCompletion() which have not yet been completed.
	pendingCompletions []*Completion
}

// NewWaitGroup returns a new WaitGroup using the given context.
func NewWaitGroup(ctx context.Context) *WaitGroup {
	return &WaitGroup{ctx: ctx}
}

// Context returns the context of all the Completions in the wait group.
func (wg *WaitGroup) Context() context.Context {
	return wg.ctx
}

// AddCompletionWithCallbacks creates a new completion, adds it to the wait
// group, and returns it. The callback will be called upon completion.
// The retryCallback will be called if the asynchronous operation fails.
// Calling retryCallback does not complete the operation, but it can cancel the
// operation if needed.
func (wg *WaitGroup) AddCompletionWithCallbacks(callback func(), retryCallback func()) *Completion {
	wg.counterLocker.Lock()
	defer wg.counterLocker.Unlock()
	c := NewCompletion(wg.ctx, callback, retryCallback)
	wg.pendingCompletions = append(wg.pendingCompletions, c)
	return c
}

// AddCompletion creates a new completion, adds it into the wait group, and
// returns it.
func (wg *WaitGroup) AddCompletion() *Completion {
	return wg.AddCompletionWithCallbacks(nil, nil)
}

// Wait blocks until all completions added by calling AddCompletion are
// completed, or the context is canceled, whichever happens first.
// Returns the context's error if it is cancelled, nil otherwise.
func (wg *WaitGroup) Wait() error {
	wg.counterLocker.Lock()
	defer wg.counterLocker.Unlock()

Loop:
	for i, comp := range wg.pendingCompletions {
		select {
		case <-comp.Completed():
			continue Loop
		case <-wg.ctx.Done():
			// Complete the remaining completions to make sure their completed
			// channels are closed.
			for _, comp := range wg.pendingCompletions[i:] {
				comp.complete(false)
			}
			break Loop
		}
	}
	wg.pendingCompletions = nil
	return wg.ctx.Err()
}

// Completion provides the Complete callback to be called when an asynchronous
// computation is completed.
type Completion struct {
	// ctx is the context of the wait group.
	ctx context.Context

	// lock is used to check and close the completed channel atomically.
	lock lock.Mutex

	// completed is the channel to be closed when Complete is called the first
	// time.
	completed chan struct{}

	// callback is called when Complete is called the first time.
	callback func()

	// retryCallback is called when the asynchronous operations fails but there is still
	// time to retry the operation.
	retryCallback func()
}

// Context returns the context of the asynchronous computation.
// If the context is cancelled, e.g. if it times out, the computation must be
// cancelled.
func (c *Completion) Context() context.Context {
	return c.ctx
}

// Complete notifies of the completion of the asynchronous computation.
// Idempotent.
func (c *Completion) Complete() {
	c.complete(true)
}

// Retry notifies of the failure of the asynchronous computation.
func (c *Completion) Retry() {
	c.lock.Lock()
	select {
	case <-c.completed:
		c.lock.Unlock() // Do not retry if already completed
	default:
		c.lock.Unlock()
		if c.retryCallback != nil {
			c.retryCallback()
		}
	}
}

// Complete notifies of the completion of the asynchronous computation.
// If this is the first time this method is called, runCallback is true, and
// the Completion was created by calling WaitGroup.AddCompletionWithCallbacks or
// NewCompletion with a non-nil callback, that callback is called.
// Idempotent.
func (c *Completion) complete(runCallback bool) {
	c.lock.Lock()
	select {
	case <-c.completed:
		c.lock.Unlock()
	default:
		close(c.completed)
		c.lock.Unlock()
		if runCallback && c.callback != nil {
			c.callback()
		}
	}
}

// Completed returns a channel that's closed when the completion is completed,
// i.e. when Complete is called the first time, or when the call to the parent
// WaitGroup's Wait terminated because the context was canceled.
func (c *Completion) Completed() <-chan struct{} {
	return c.completed
}

// NewCompletion creates a Completion which calls a function upon Complete() or Retry().
func NewCompletion(ctx context.Context, callback func(), retryCallback func()) *Completion {
	return &Completion{
		ctx:           ctx,
		completed:     make(chan struct{}),
		callback:      callback,
		retryCallback: retryCallback,
	}
}
