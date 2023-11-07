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
// Sinks: operators that consume the observable to produce a value.
//

// First returns the first item from 'src' observable and then cancels
// the subscription. Blocks until first item is observed or the stream
// is completed. If the observable completes without emitting items
// then io.EOF error is returned.
func First[T any](ctx context.Context, src Observable[T]) (item T, err error) {
	subCtx, cancel := context.WithCancel(ctx)
	var taken atomic.Bool
	errs := make(chan error)
	src.Observe(subCtx,
		func(x T) {
			if !taken.CompareAndSwap(false, true) {
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

	if taken.Load() {
		// We got the item, ignore any error.
		err = nil
	} else if err == nil {
		// No error and no item => EOF
		err = io.EOF
	}

	return
}

// Last returns the last item from 'src' observable. Blocks until
// the stream has been completed. If no items are observed then
// io.EOF error is returned.
func Last[T any](ctx context.Context, src Observable[T]) (item T, err error) {
	errs := make(chan error)
	var taken atomic.Bool
	src.Observe(
		ctx,
		func(x T) {
			item = x
			taken.Store(true)
		},
		func(err error) {
			errs <- err
			close(errs)
		})

	err = <-errs
	if taken.Load() {
		// We got the item, ignore any error.
		err = nil
	} else if err == nil {
		// No error and no item => EOF
		err = io.EOF
	}
	return item, err
}

// ToSlice converts an Observable into a slice.
//
//	ToSlice(ctx, Range(1,4))
//	  => ([]int{1,2,3}, nil)
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

type toChannelOpts struct {
	bufferSize int
	errorChan  chan error
}

type ToChannelOpt func(*toChannelOpts)

// WithBufferSize sets the buffer size of the channel returned by ToChannel.
func WithBufferSize(n int) ToChannelOpt {
	return func(o *toChannelOpts) {
		o.bufferSize = n
	}
}

// WithErrorChan asks ToChannel to send completion error to the provided channel.
func WithErrorChan(errCh chan error) ToChannelOpt {
	return func(o *toChannelOpts) {
		o.errorChan = errCh
	}
}

// ToChannel converts an observable into a channel.
// When the provided context is cancelled the underlying subscription is cancelled
// and the channel is closed. To receive completion errors use [WithErrorChan].
//
//	items <- ToChannel(ctx, Range(1,4))
//	a := <- items
//	b := <- items
//	c := <- items
//	_, ok := <- items
//	  => a=1, b=2, c=3, ok=false
func ToChannel[T any](ctx context.Context, src Observable[T], opts ...ToChannelOpt) <-chan T {
	var o toChannelOpts
	for _, opt := range opts {
		opt(&o)
	}
	items := make(chan T, o.bufferSize)
	src.Observe(
		ctx,
		func(item T) { items <- item },
		func(err error) {
			close(items)
			if o.errorChan != nil {
				o.errorChan <- err
			}
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
