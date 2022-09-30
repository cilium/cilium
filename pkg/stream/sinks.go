// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package stream

import (
	"context"
	"io"
	"sync"
	"sync/atomic"
)

//
// Sinks: operators that "sink" the observable into something.
//

// First returns the first item from 'src' observable and then cancels
// the subscription. If the observable completes without emitting items
// then io.EOF error is returned.
func First[T any](ctx context.Context, src Observable[T]) (item T, err error) {
	subCtx, cancel := context.WithCancel(ctx)
	taken := uint32(0)
	errs := make(chan error)
	src.Observe(subCtx,
		func(x T) {
			if !atomic.CompareAndSwapUint32(&taken, 0, 1) {
				return
			}
			item = x
			cancel()
		},
		func(err error) {
			errs <- err
			close(errs)
		})

	err = <-errs

	if atomic.LoadUint32(&taken) == 1 {
		// We got the item, ignore any error.
		err = nil
	} else if err == nil {
		// No error and no item => EOF
		err = io.EOF
	}

	return
}

// Last returns the last item from 'src' observable.
func Last[T any](ctx context.Context, src Observable[T]) (item T, err error) {
	errs := make(chan error)
	taken := uint32(0)
	src.Observe(
		ctx,
		func(x T) {
			item = x
			atomic.StoreUint32(&taken, 1)
		},
		func(err error) {
			errs <- err
			close(errs)
		})

	err = <-errs
	if atomic.LoadUint32(&taken) == 1 {
		// We got the item, ignore any error.
		err = nil
	} else if err == nil {
		// No error and no item => EOF
		err = io.EOF
	}
	return item, err
}

// ToSlice converts an Observable into a slice.
func ToSlice[T any](ctx context.Context, src Observable[T]) (items []T, err error) {
	errs := make(chan error)
	items = make([]T, 0)
	src.Observe(
		ctx,
		func(item T) {
			items = append(items, item)
		},
		func(err error) {
			errs <- err
			close(errs)
		})
	return items, <-errs
}

// ToChannel converts an observable into an item of channels. Error, or nil if normal
// completion, is delivered to the supplied error channel.
func ToChannel[T any](ctx context.Context, errs chan<- error, src Observable[T]) <-chan T {
	items := make(chan T)
	src.Observe(
		ctx,
		func(item T) { items <- item },
		func(err error) {
			close(items)
			errs <- err
		})
	return items
}

// Discard discards all items from 'src'.
func Discard[T any](ctx context.Context, src Observable[T]) {
	src.Observe(ctx,
		func(item T) {},
		func(err error) {})
}

// ObserveWithWaitGroup is like Observe(), but adds to a WaitGroup and calls
// Done() when complete.
func ObserveWithWaitGroup[T any](ctx context.Context, wg *sync.WaitGroup, src Observable[T], next func(T), complete func(error)) {
	wg.Add(1)
	src.Observe(
		ctx,
		next,
		func(err error) {
			complete(err)
			wg.Done()
		})
}
