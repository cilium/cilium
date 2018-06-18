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

// Package completion implements a variant of sync.WaitGroup that is associated
// with a context.Context.
//
// A WaitGroup is created by calling NewWaitGroup with the context:
//
//    wg := completion.NewWaitGroup(ctx)
//
// For each concurrent computation to wait for, a Completion is created by
// calling AddCompletion and then passing it to the concurrent computation:
//
//    comp1 := wg.AddCompletion()
//    DoSomethingConcurrently(..., comp1)
//    comp2 := wg.AddCompletion()
//    DoSomethingElse(..., comp2)
//
// The Completion type provides the WaitGroup's context and the Complete
// method:
//
//    func (c *Completion) Context() context.Context
//    func (c *Completion) Complete()
//    func (c *Completion) Completed() <-chan struct{}
//
// The Complete method must be called when the concurrent computation is
// completed, for instance:
//
//    func DoSomethingConcurrently(..., comp Completion) {
//        ...
//        go func() {
//            ...
//            // Computation is completed successfully.
//            comp.Complete()
//        }()
//        ...
//    }
//
// Once all Completions are created, one can wait for the completion of all
// of the Completions by calling Wait:
//
//    err := wg.Wait()
//
// Wait blocks until either all Completions are completed, or the context is
// canceled (e.g. times out), whichever happens first. The returned error is
// non-nil in the case the context is canceled, nil otherwise.
//
// A Completion can also be created with a callback, which is called at most
// once when the Completion is successfully completed before the context is
// cancelled:
//
//    comp := wg.AddCompletionWithCallbacks(func() { fmt.Println("completed') },
//                                          func() { fmt.Println("failed') })
//
// The callback is called in the goroutine which calls Complete the first time.
package completion
