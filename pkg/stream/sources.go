// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package stream

import (
	"context"
	"sync"
)

// Just creates an observable with a single item.
func Just[T any](item T) Observable[T] {
	return FuncObservable[T](
		func(ctx context.Context, next func(T), complete func(error)) {
			go func() {
				if err := ctx.Err(); err != nil {
					complete(err)
				} else {
					next(item)
					complete(nil)
				}
			}()
		})
}

// Stuck creates an observable that never emits anything and
// just waits for the context to be cancelled.
// Mainly meant for testing.
func Stuck[T any]() Observable[T] {
	return FuncObservable[T](
		func(ctx context.Context, next func(T), complete func(error)) {
			go func() {
				<-ctx.Done()
				complete(ctx.Err())
			}()
		})
}

// Error creates an observable that fails immediately with given error.
func Error[T any](err error) Observable[T] {
	return FuncObservable[T](
		func(ctx context.Context, next func(T), complete func(error)) {
			go complete(err)
		})
}

// Empty creates an empty observable that completes immediately.
func Empty[T any]() Observable[T] {
	return Error[T](nil)
}

// FromSlice converts a slice into an Observable.
func FromSlice[T any](items []T) Observable[T] {
	// Emit items in chunks to reduce overhead of mutex in ctx.Err().
	const chunkSize = 64
	return FuncObservable[T](
		func(ctx context.Context, next func(T), complete func(error)) {
			go func() {
				for chunk := 0; chunk < len(items); chunk += chunkSize {
					if err := ctx.Err(); err != nil {
						complete(err)
						return
					}
					for i := chunk; i < len(items) && i < chunk+chunkSize; i++ {
						next(items[i])
					}
				}
				complete(nil)
			}()
		})
}

// FromChannel creates an observable from a channel. The channel is consumed
// by the first observer.
func FromChannel[T any](in <-chan T) Observable[T] {
	return FuncObservable[T](
		func(ctx context.Context, next func(T), complete func(error)) {
			go func() {
				done := ctx.Done()
				for {
					select {
					case <-done:
						complete(ctx.Err())
						return
					case v, ok := <-in:
						if !ok {
							complete(nil)
							return
						}
						next(v)
					}
				}
			}()
		})
}

// Range creates an observable that emits integers in range from...to-1.
func Range(from, to int) Observable[int] {
	return FuncObservable[int](
		func(ctx context.Context, next func(int), complete func(error)) {
			go func() {
				for i := from; i < to; i++ {
					if ctx.Err() != nil {
						break
					}
					next(i)
				}
				complete(ctx.Err())
			}()
		})
}

type mcastSubscriber[T any] struct {
	next     func(T)
	complete func(error)
}

type MulticastOpt func(o mcastOpts)

type mcastOpts struct {
	emitLatest bool
}

func (o mcastOpts) apply(opts []MulticastOpt) mcastOpts {
	for _, opt := range opts {
		opt(o)
	}
	return o
}

func (o mcastOpts) setEmitLatest() {
	o.emitLatest = true
}

// Multicast options
var (
	// Emit the latest seen item when subscribing.
	EmitLatest = mcastOpts.setEmitLatest
)

// Multicast creates an observable that "multicasts" the emitted items to all observers.
func Multicast[T any](opts ...MulticastOpt) (mcast Observable[T], next func(T), complete func(error)) {
	var (
		mu          sync.Mutex
		subId       int
		subs        = make(map[int]mcastSubscriber[T])
		latestValue T
		completed   bool
		completeErr error
		haveLatest  bool
		opt         = mcastOpts{}.apply(opts)
	)

	next = func(item T) {
		mu.Lock()
		if opt.emitLatest {
			latestValue = item
			haveLatest = true
		}
		for _, sub := range subs {
			sub.next(item)
		}
		mu.Unlock()
	}

	complete = func(err error) {
		mu.Lock()
		for _, sub := range subs {
			sub.complete(err)
		}
		completed = true
		completeErr = err
		mu.Unlock()
	}

	mcast = FuncObservable[T](
		func(subCtx context.Context, next func(T), complete func(error)) {
			go func() {
				mu.Lock()
				defer mu.Unlock()

				if completed {
					complete(completeErr)
					return
				}

				// Wrap the subCtx so that it gets cancelled also when upstream
				// completes.
				subCtx, cancel := context.WithCancel(subCtx)

				thisId := subId
				subId++
				subs[thisId] = mcastSubscriber[T]{
					next,
					func(err error) {
						cancel()
						complete(err)
					},
				}

				if opt.emitLatest && haveLatest {
					next(latestValue)
				}

				go func() {
					<-subCtx.Done()
					mu.Lock()
					defer mu.Unlock()
					delete(subs, thisId)
				}()
			}()
		})
	return
}
