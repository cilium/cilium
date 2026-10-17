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
// calling AddCompletionWithCallback and then passing it to the concurrent computation:
//
//	comp1 := wg.AddCompletionWithCallback(nil, nil)
//	DoSomethingConcurrently(..., comp1)
//	comp2 := wg.AddCompletionWithCallback(nil, nil)
//	DoSomethingElse(..., comp2)
//
// The Completion type provides the Complete and Completed() methods:
//
//	func (c *Completion) Complete()
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
// Cancel cancels the group's context and synchronously drains pending callbacks
// and owner cleanup through Wait, discarding its error. Canceling the context
// alone does not perform this cleanup. Registration must finish before either
// method is called. Neither may be called from a completion callback or owner
// cleanup hook, or while holding locks those hooks need.
//
// A Completion can also be created with a callback, which is called at most
// once when the Completion is completed, including by Wait or Cancel:
//
//	comp := wg.AddCompletionWithCallback(nil, func(err error) {
//	    if err == nil {
//	        fmt.Println("completed')
//	    }
//	})
//
// The callback is called in the goroutine which first completes it, either
// through Complete, Wait, or Cancel.
// The callback is called with an non-nil error if the associated concurrent
// operation fails. Error values 'context.DeadlineExceeded' and
// 'context.Canceled' are passed if the WaitGroup's context times out or is
// canceled. Note that the context is canceled also if any of the other
// completions in the WaitGroup fails, and the non-failing completions will
// have their callbacks called with 'context.Canceled'.
package completion
