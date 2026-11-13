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
// afterward. Both methods synchronously run owner cleanup, so they must not be
// called from cleanup hooks or while holding locks those hooks need.
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
// Wait, which does not wait on a cancelled context. No owner cleanup remains
// in progress when it returns. Cancel discards the wait error; a subsequent
// Wait cannot retrieve it. Harmless if called after Wait().
func (wg *WaitGroup) Cancel() {
	wg.cancel()
	_ = wg.Wait()
}

// Owner provides optional debug correlation and wait-time cleanup for a
// completion created with AddCompletion.
type Owner interface {
	ID() string
	CleanupAfterWait(*Completion)
}

// AddCompletion creates a new completion, adds it to the wait group, and returns
// it. Complete reports the operation's success or failure to the group.
func (wg *WaitGroup) AddCompletion(owner Owner) *Completion {
	wg.counterLocker.Lock()
	defer wg.counterLocker.Unlock()
	c := &Completion{
		owner:     owner,
		cancel:    wg.cancel,
		completed: make(chan struct{}),
	}
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
// the context is canceled or times out, whichever happens first.
// Pending completions are settled and their owner cleanup finishes before
// this returns.
// Returns any completion error if there are completions, overridden by context
// error if the context times out. The context error is returned for empty WaitGroups
// and for subsequent Wait calls. The context error is nil for the first Wait call if
// the context was not cancelled or timed out.
// Further calls return context.DeadlineExceeded if the context timed out, or
// context.Canceled otherwise.
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
			// Context was canceled or timed out. Complete the remaining completions
			// (if any) to make sure their completed channels are closed.
			ctxErr := wg.ctx.Err()
			for _, c := range wg.pendingCompletions[i:] {
				// 'comp' may have already completed on a different error
				compErr := c.Complete(ctxErr)
				if c.owner != nil {
					c.owner.CleanupAfterWait(c)
				}
				err = updateError(err, compErr) // Keep the most severe error value we encounter
			}
			// return without error if all completions completed without an error, even
			// if the context was canceled or timed out. This resolves a
			// Done/completion race in favor of completion.
			if err != nil {
				// override error with the hanging completion if deadline exceeded
				if errors.Is(ctxErr, context.DeadlineExceeded) {
					err = fmt.Errorf("Waiting on %s: %w", comp.Id(), ctxErr)
				}
			}
			break Loop
		}
	}
	// return context error if there were no completions
	if len(wg.pendingCompletions) == 0 {
		err = wg.ctx.Err()
	}
	wg.pendingCompletions = nil
	wg.cancel()
	return err
}

// Completion records the result of an asynchronous computation.
type Completion struct {
	// cancel is used to cancel the WaitGroup the completion belongs in case of an error
	cancel context.CancelFunc

	// lock is used to check and close the completed channel atomically.
	lock lock.Mutex

	// completed is the channel to be closed when Complete is called the first
	// time.
	completed chan struct{}

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
		err = c.err // return the error 'c' already completed with
	default:
		c.err = err
		// Signal failure without draining while holding the completion lock.
		// Wait or Cancel will settle the other completions and clean up owners.
		if err != nil {
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
