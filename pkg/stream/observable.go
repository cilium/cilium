// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

// The stream package provides utilities for working with observable streams.
// Any type that implements the Observable interface can be transformed and
// consumed with these utilities.
package stream

import "context"

// Observable defines the Observe method for observing a stream of values.
type Observable[T any] interface {
	// Observe a stream of values as long as the given context is valid.
	// 'next' is called for each item, and finally 'complete' is called
	// when the stream is complete, or an error has occurred.
	//
	// 'next' and 'complete' are never called concurrently.
	Observe(ctx context.Context, next func(T), complete func(error))
}

// FuncObservable implements Observe with a function.
type FuncObservable[T any] func(context.Context, func(T), func(error))

func (f FuncObservable[T]) Observe(ctx context.Context, next func(T), complete func(error)) {
	f(ctx, next, complete)
}
