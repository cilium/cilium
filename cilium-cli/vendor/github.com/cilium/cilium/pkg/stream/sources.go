// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package stream

import (
	"context"

	"github.com/cilium/cilium/pkg/lock"
)

// Just creates an observable that emits a single item and completes.
//
//	xs, err := ToSlice(ctx, Just(1))
//	  => xs == []int{1}, err == nil
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
//
//	failErr = errors.New("fail")
//	xs, err := ToSlice(ctx, Error[int](failErr))
//	  => xs == []int{}, err == failErr
func Error[T any](err error) Observable[T] {
	return FuncObservable[T](
		func(ctx context.Context, next func(T), complete func(error)) {
			go complete(err)
		})
}

// Empty creates an "empty" observable that completes immediately.
//
//	xs, err := ToSlice(Empty[int]())
//	  => xs == []int{}, err == nil
func Empty[T any]() Observable[T] {
	return Error[T](nil)
}

// FromSlice converts a slice into an Observable.
//
//	ToSlice(ctx, FromSlice([]int{1,2,3})
//	  => []int{1,2,3}
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
//
//	values := make(chan int)
//	go func() {
//		values <- 1
//		values <- 2
//		values <- 3
//		close(values)
//	}()
//	obs := FromChannel(values)
//	xs, err := ToSlice(ctx, obs)
//	  => xs == []int{1,2,3}, err == nil
//
//	xs, err = ToSlice(ctx, obs)
//	  => xs == []int{}, err == nil
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
//
//	ToSlice(ctx, Range(1,2,3)) => []int{1,2,3}
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
	complete func()
}

type MulticastOpt func(o *mcastOpts)

type mcastOpts struct {
	emitLatest bool
}

func (o mcastOpts) apply(opts []MulticastOpt) mcastOpts {
	for _, opt := range opts {
		opt(&o)
	}
	return o
}

// Multicast options
var (
	// Emit the latest seen item when subscribing.
	EmitLatest = func(o *mcastOpts) { o.emitLatest = true }
)

// Multicast creates an observable that "multicasts" the emitted items to all observers.
//
//	mcast, next, complete := Multicast[int]()
//	next(1) // no observers, none receives this
//	sub1 := ToChannel(ctx, mcast, WithBufferSize(10))
//	sub2 := ToChannel(ctx, mcast, WithBufferSize(10))
//	next(2)
//	next(3)
//	complete(nil)
//	  => sub1 == sub2 == [2,3]
//
//	mcast, next, complete = Multicast[int](EmitLatest)
//	next(1)
//	next(2) // "EmitLatest" tells Multicast to keep this
//	x, err := First(ctx, mcast)
//	  => x == 2, err == nil
func Multicast[T any](opts ...MulticastOpt) (mcast Observable[T], next func(T), complete func(error)) {
	var (
		mu          lock.Mutex
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
		defer mu.Unlock()
		if completed {
			return
		}
		if opt.emitLatest {
			latestValue = item
			haveLatest = true
		}
		for _, sub := range subs {
			sub.next(item)
		}
	}

	complete = func(err error) {
		mu.Lock()
		defer mu.Unlock()
		completed = true
		completeErr = err
		for _, sub := range subs {
			sub.complete()
		}
		subs = nil
	}

	mcast = FuncObservable[T](
		func(ctx context.Context, subNext func(T), subComplete func(error)) {
			mu.Lock()
			if completed {
				mu.Unlock()
				go subComplete(completeErr)
				return
			}

			subCtx, cancel := context.WithCancel(ctx)
			thisId := subId
			subId++
			subs[thisId] = mcastSubscriber[T]{
				subNext,
				cancel,
			}

			// Continue subscribing asynchronously so caller is not blocked.
			go func() {
				if opt.emitLatest && haveLatest {
					subNext(latestValue)
				}
				mu.Unlock()

				// Wait for cancellation by observer, or completion from upstream.
				<-subCtx.Done()

				// Remove the observer and complete.
				var err error
				mu.Lock()
				delete(subs, thisId)
				if completed {
					err = completeErr
				} else {
					err = subCtx.Err()
				}
				mu.Unlock()
				subComplete(err)
			}()
		})

	return
}
