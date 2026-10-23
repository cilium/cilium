// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package completion

import (
	"context"
	"errors"
	"fmt"

	"github.com/cilium/cilium/pkg/lock"
)

// WaitGroup waits for a collection of Completions to complete.
// Register all completions before calling Wait or Cancel; no more may be added
// afterward. Both methods synchronously run callbacks and owner cleanup, so they
// must not be called from those hooks or while holding locks the hooks need.
type WaitGroup struct {
	// ctx is the context of all the Completions in the wait group.
	ctx context.Context

	// cancel cancels the context without draining completions.
	cancel context.CancelFunc

	// counterLocker serializes registration and draining. Registration must
	// finish before Wait or Cancel is called.
	counterLocker lock.Mutex

	// pendingCompletions is the list of Completions added to the wait group
	// which have not yet been completed.
	pendingCompletions []*Completion
}

// NewWaitGroup returns a new WaitGroup using the given context. Its internal
// context is canceled when a completion fails, Wait returns, or Cancel is called.
// Callers must eventually call Wait or Cancel to release resources and settle
// pending completions, even if the context has already been canceled.
func NewWaitGroup(ctx context.Context) *WaitGroup {
	ctx2, cancel := context.WithCancel(ctx)
	return &WaitGroup{ctx: ctx2, cancel: cancel}
}

// Cancel cancels the underlying context and drains pending completions through
// Wait, which does not wait on a cancelled context. No completion callbacks or
// owner cleanup remain in progress when it returns. Cancel discards the wait
// error; a subsequent Wait cannot retrieve it. Harmless if called after Wait().
func (wg *WaitGroup) Cancel() {
	wg.cancel()
	_ = wg.Wait()
}

// Owner provides optional debug correlation and wait-time cleanup for a
// completion created with AddCompletionWithCallback.
type Owner interface {
	ID() string
	CleanupAfterWait(*Completion)
}

// AddCompletionWithCallback creates a new completion, adds it to the wait
// group, and returns it. The callback will be called upon completion.
// Completion can complete in a failure (err != nil)
func (wg *WaitGroup) AddCompletionWithCallback(owner Owner, callback func(err error)) *Completion {
	wg.counterLocker.Lock()
	defer wg.counterLocker.Unlock()
	c := NewCompletion(owner, wg.cancel, callback)
	wg.pendingCompletions = append(wg.pendingCompletions, c)
	return c
}

// updateError updates the error value to be returned from Wait()
// so that we return the most severe or consequential error
// encountered. The order of importance of error values is (from
// highest to lowest):
// 1. Non-context errors
// 2. context.Canceled
// 3. context.DeadlineExceeded
// 4. nil
func updateError(old, new error) error {
	if new == nil {
		return old
	}
	// 'old' error is overridden by a non-nil 'new' error value if
	// 1. 'old' is nil, or
	// 2. 'old' is a timeout, or
	// 3. 'old' is a cancel and the 'new' error value is not a timeout
	if old == nil || errors.Is(old, context.DeadlineExceeded) || (errors.Is(old, context.Canceled) && !errors.Is(new, context.DeadlineExceeded)) {
		return new
	}
	return old
}

// Wait blocks until all completions added to the wait group are completed, or
// the context is canceled, whichever happens first.
// No callbacks of the completions in this wait group will be called after
// this returns.
// Returns the error value of one of the completions, if available, or the
// error value of the Context otherwise. A canceled context is reported even
// when no completions remain pending.
func (wg *WaitGroup) Wait() error {
	wg.counterLocker.Lock()
	defer wg.counterLocker.Unlock()

	var err error
Loop:
	for i, comp := range wg.pendingCompletions {
		select {
		case <-comp.Completed():
			err = updateError(err, comp.Err()) // Keep the most severe error value we encounter
			continue Loop
		case <-wg.ctx.Done():
			// Complete the remaining completions (if any) to make sure their completed
			// channels are closed.
			ctxErr := wg.ctx.Err()
			for _, c := range wg.pendingCompletions[i:] {
				// 'comp' may have already completed on a different error
				compErr := c.Complete(ctxErr)
				if c.owner != nil {
					c.owner.CleanupAfterWait(c)
				}
				err = updateError(err, compErr) // Keep the most severe error value we encounter
			}
			// override error with the hanging completion if deadline exceeded
			if errors.Is(ctxErr, context.DeadlineExceeded) {
				err = fmt.Errorf("Waiting on %s: %w", comp.Id(), ctxErr)
			}
			break Loop
		}
	}
	wg.pendingCompletions = nil
	// Observe cancellation before Wait cancels its own context, including
	// when the group is empty or all completions have already succeeded.
	if err == nil {
		err = wg.ctx.Err()
	}
	wg.cancel()
	return err
}

// Completion provides the Complete callback to be called when an asynchronous
// computation is completed.
type Completion struct {
	// cancel is used to cancel the WaitGroup the completion belongs in case of an error
	cancel context.CancelFunc

	// lock is used to check and close the completed channel atomically.
	lock lock.Mutex

	// completed is the channel to be closed when Complete is called the first
	// time.
	completed chan struct{}

	// callback is called when Complete is called the first time.
	callback func(err error)

	// owner provides an optional debug ID and wait-time cleanup hook.
	owner Owner

	// err is the error the completion completed with
	err error
}

// Err returns a non-nil error if the completion ended in error
func (c *Completion) Err() error {
	c.lock.Lock()
	defer c.lock.Unlock()
	return c.err
}

func (c *Completion) Id() string {
	if c.owner == nil {
		return ""
	}
	return c.owner.ID()
}

// Complete notifies of the completion of the asynchronous computation.
// Idempotent.
// If the operation completed successfully 'err' is passed as nil.
// Returns the error state the completion completed with, which is
// generally different from 'err' if already completed.
func (c *Completion) Complete(err error) error {
	c.lock.Lock()
	select {
	case <-c.completed:
		err = c.err // return the error 'c' completed with
	default:
		c.err = err
		if c.callback != nil {
			// We must call the callbacks synchronously to guarantee
			// that they are actually called before Wait() returns.
			c.callback(err)
		}
		// Signal failure without draining while holding the completion lock.
		// Wait or Cancel will settle the other completions and clean up owners.
		if err != nil && c.cancel != nil {
			c.cancel()
		}
		close(c.completed)
	}
	c.lock.Unlock()
	return err
}

// Completed returns a channel that's closed when the completion is completed,
// i.e. when Complete is called the first time, or when the call to the parent
// WaitGroup's Wait terminated because the context was canceled.
func (c *Completion) Completed() <-chan struct{} {
	return c.completed
}

// NewCompletion creates a Completion which calls a function upon Complete().
// 'cancel' is called if the associated operation fails for any reason.
func NewCompletion(owner Owner, cancel context.CancelFunc, callback func(err error)) *Completion {
	return &Completion{
		owner:     owner,
		cancel:    cancel,
		completed: make(chan struct{}),
		callback:  callback,
	}
}
