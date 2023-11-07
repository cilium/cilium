// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

// The stream package provides utilities for working with observable streams.
// Any type that implements the Observable interface can be transformed and
// consumed with these utilities.
package stream

import "context"

// Observable defines the Observe method for observing a stream of values.
//
// Also see https://reactivex.io/documentation/observable.html for in-depth
// description of observables.
//
// For interactive diagrams see https://rxmarbles.com/.
type Observable[T any] interface {
	// Observe a stream of values as long as the given context is valid.
	// 'next' is called for each item, and finally 'complete' is called
	// when the stream is complete, or an error has occurred.
	//
	// Observable implementations are allowed to call 'next' and 'complete'
	// from any goroutine, but never concurrently.
	Observe(ctx context.Context, next func(T), complete func(error))
}

// FuncObservable implements the Observable interface with a function.
//
// This provides a convenient way of creating new observables without having
// to introduce a new type:
//
//	 var Ones Observable[int] =
//	 	FuncObservable[int](
//			func(ctx context.Context, next func(int), complete func(error)) {
//				go func() {
//					defer complete(nil)
//					for ctx.Err() == nil {
//						next(1)
//					}
//				}()
//			})
//
// versus with a new type:
//
//	type onesObservable struct {}
//
//	func (o onesObservable) Observe(ctx context.Context, next func(int), complete func(error)) {
//		go func() {
//			defer complete(nil)
//			for ctx.Err() == nil {
//				next(1)
//			}
//		}()
//	}
type FuncObservable[T any] func(context.Context, func(T), func(error))

func (f FuncObservable[T]) Observe(ctx context.Context, next func(T), complete func(error)) {
	f(ctx, next, complete)
}
