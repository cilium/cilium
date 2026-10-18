// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

// Package completion implements a variant of sync.WaitGroup that is associated
// with a context.Context.
//
// A WaitGroup is created by calling NewWaitGroup with the context:
//
//	wg := completion.NewWaitGroup(ctx)
//
// For each concurrent computation to wait for, a Completion is created by
// calling AddCompletion and then passing it to the concurrent computation:
//
//	comp1 := wg.AddCompletion(nil)
//	DoSomethingConcurrently(..., comp1)
//	comp2 := wg.AddCompletion(nil)
//	DoSomethingElse(..., comp2)
//
// The Completion type provides the Complete and Completed() methods:
//
//	func (c *Completion) Complete(err error) error
//	func (c *Completion) Completed() <-chan struct{}
//
// The Complete method must be called when the concurrent computation is
// completed, for instance:
//
//	func DoSomethingConcurrently(..., comp Completion) {
//	    ...
//	    go func() {
//	        ...
//	        // Computation is completed successfully.
//	        comp.Complete(nil)
//	    }()
//	    ...
//	}
//
// Once all Completions are created, one can wait for the completion of all
// of the Completions by calling Wait:
//
//	err := wg.Wait()
//
// Wait blocks until all Completions are completed, or the context is canceled or
// times out. A failed operation also cancels the context. Before returning, Wait
// settles any remaining Completions and drains the group.
//
// With Completions, Wait returns nil if they all completed successfully, even if
// the context was canceled or timed out. Otherwise, it returns a completion
// error, overridden by the context error if Wait observes a timeout.
//
// For an empty WaitGroup, Wait returns the context error, which is nil if the
// context has not been canceled or timed out. Wait cancels the context before
// returning, so subsequent calls return context.DeadlineExceeded if the context
// timed out, or context.Canceled otherwise.
//
// If the caller abandons the operation before Wait, it must call Cancel instead.
// Cancel cancels the group's context and synchronously settles pending completions
// and runs owner cleanup through Wait, discarding its error. Canceling the context
// alone does not perform this cleanup. Registration must finish before either
// method is called. Neither may be called from an owner cleanup hook or while
// holding locks that hook needs.
package completion
