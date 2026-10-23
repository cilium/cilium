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
// Wait blocks until either all Completions are completed, or the context is
// canceled, times out, or any of the concurrent operations associated with
// the WaitGroup fails, whichever happens first. The returned error is
// nil if all the concurrent operations are successfully completed and the
// context has not been canceled, a non-nil error otherwise.
//
// If the caller abandons the operation before Wait, it must call Cancel instead.
// Cancel cancels the group's context and synchronously settles pending completions
// and runs owner cleanup through Wait, discarding its error. Canceling the context
// alone does not perform this cleanup. Registration must finish before either
// method is called. Neither may be called from an owner cleanup hook or while
// holding locks that hook needs.
package completion
