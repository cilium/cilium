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

	// cancel is the function to call if any pending operation fails
	cancel context.CancelFunc

	// counterLocker locks all calls to AddCompletion and Wait, which must not
	// be called concurrently.
	counterLocker lock.Mutex

	// pendingCompletions is the list of Completions returned by
	// AddCompletion() which have not yet been completed.
	pendingCompletions []*Completion
}

// NewWaitGroup returns a new WaitGroup using the given context.
func NewWaitGroup(ctx context.Context) *WaitGroup {
	ctx2, cancel := context.WithCancel(ctx)
	return &WaitGroup{ctx: ctx2, cancel: cancel}
}

// Context returns the context of all the Completions in the wait group.
func (wg *WaitGroup) Context() context.Context {
	return wg.ctx
}

// AddCompletionWithCallback creates a new completion, adds it to the wait
// group, and returns it. The callback will be called upon completion.
// Completion can complete in a failure (err != nil)
func (wg *WaitGroup) AddCompletionWithCallback(callback func(err error)) *Completion {
	wg.counterLocker.Lock()
	defer wg.counterLocker.Unlock()
	c := NewCompletion(wg, callback)
	wg.pendingCompletions = append(wg.pendingCompletions, c)
	return c
}

// AddCompletion creates a new completion, adds it into the wait group, and
// returns it.
func (wg *WaitGroup) AddCompletion() *Completion {
	return wg.AddCompletionWithCallback(nil)
}

// Wait blocks until all completions added by calling AddCompletion are
// completed, or the context is canceled, whichever happens first.
// Returns the context's error if it is cancelled, nil otherwise.
// No callbacks of the completions in this wait group will be called after
// this returns.
// Returns the error value of one of the completions, if available, or the
// error value of the WaitGroup otherwise.
func (wg *WaitGroup) Wait() error {
	wg.counterLocker.Lock()
	defer wg.counterLocker.Unlock()

	var err error
Loop:
	for i, comp := range wg.pendingCompletions {
		select {
		case <-comp.Completed():
			err = comp.Error
			continue Loop
		case <-wg.ctx.Done():
			// Complete the remaining completions to make sure their completed
			// channels are closed.
			wgErr := wg.ctx.Err() // context.Canceled or context.DeadlineExeeded
			for _, comp := range wg.pendingCompletions[i:] {
				comp.Complete(wgErr)
				// Note if the completion errored
				if err == nil && comp.Error != wgErr {
					err = comp.Error
				}
			}
			if err == nil {
				err = wgErr
			}
			break Loop
		}
	}
	wg.pendingCompletions = nil
	return err
}

// Completion provides the Complete callback to be called when an asynchronous
// computation is completed.
type Completion struct {
	// wg is the wait group the completion belongs to
	wg *WaitGroup

	// lock is used to check and close the completed channel atomically.
	lock lock.Mutex

	// completed is the channel to be closed when Complete is called the first
	// time.
	completed chan struct{}

	// callback is called when Complete is called the first time.
	callback func(err error)

	// err is the error the completion completed with
	Error error
}

// Context returns the context of the asynchronous computation.
// If the context is cancelled, e.g. if it times out, the computation must be
// cancelled.
func (c *Completion) Context() context.Context {
	if c.wg == nil {
		return context.Background()
	}
	return c.wg.ctx
}

// Complete notifies of the completion of the asynchronous computation.
// Idempotent.
// If the operation completed successfully 'err' is passed as nil.
func (c *Completion) Complete(err error) {
	c.lock.Lock()
	select {
	case <-c.completed:
		c.lock.Unlock()
	default:
		if c.callback != nil {
			// We must call the callbacks synchronously to guarantee
			// that they are actually called before Wait() returns.
			c.callback(err)
		}
		// Terminate the WaitGroup on failure
		if err != nil {
			c.Error = err
			c.wg.cancel()
		}
		close(c.completed)
		c.lock.Unlock()
	}
}

// Completed returns a channel that's closed when the completion is completed,
// i.e. when Complete is called the first time, or when the call to the parent
// WaitGroup's Wait terminated because the context was canceled.
func (c *Completion) Completed() <-chan struct{} {
	return c.completed
}

// NewCompletion creates a Completion which calls a function upon Complete().
// WaitGroup 'wg' is canceled if the associated operation fails for any
// reason.
func NewCompletion(wg *WaitGroup, callback func(err error)) *Completion {
	return &Completion{
		wg:        wg,
		completed: make(chan struct{}),
		callback:  callback,
	}
}
