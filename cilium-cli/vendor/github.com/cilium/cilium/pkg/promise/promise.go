// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package promise

import (
	"context"
	"sync"

	"github.com/cilium/cilium/pkg/lock"
)

// A promise for a future value.
type Promise[T any] interface {
	// Await blocks until the value is resolved or rejected.
	Await(context.Context) (T, error)
}

// Resolver can resolve or reject a promise.
// These methods are separate from 'Promise' to make it clear where the promise is resolved
// from.
type Resolver[T any] interface {
	// Resolve a promise. Unblocks all Await()s. Future calls of Await()
	// return the resolved value immediately.
	//
	// Only the first call to resolve (or reject) has an effect and
	// further calls are ignored.
	Resolve(T)

	// Reject a promise with an error.
	Reject(error)
}

// New creates a new promise for value T.
// Returns a resolver and the promise.
func New[T any]() (Resolver[T], Promise[T]) {
	promise := &promise[T]{}
	promise.cond = sync.NewCond(promise)
	return promise, promise
}

const (
	promiseUnresolved = iota
	promiseResolved
	promiseRejected
)

type promise[T any] struct {
	lock.Mutex
	cond  *sync.Cond
	state int
	value T
	err   error
}

// Resolve informs all other codepaths who are Await()ing on the received
// promise that T is now successfully initialized and available for usage.
//
// Initialization logic for T should either call Resolve() or Reject(), and
// must not call these functions more than once.
func (p *promise[T]) Resolve(value T) {
	p.Lock()
	defer p.Unlock()
	if p.state != promiseUnresolved {
		return
	}
	p.state = promiseResolved
	p.value = value
	p.cond.Broadcast()
}

// Reject informs all other codepaths who are Await()ing on the received
// promise that T could not be initialized and cannot be used to due the
// specified error reason.
//
// Initialization logic for T should either call Resolve() or Reject(), and
// must not call these functions more than once.
func (p *promise[T]) Reject(err error) {
	p.Lock()
	defer p.Unlock()
	if p.state != promiseUnresolved {
		return
	}
	p.state = promiseRejected
	p.err = err
	p.cond.Broadcast()
}

// Await blocks until the promise has been resolved, rejected or context cancelled.
func (p *promise[T]) Await(ctx context.Context) (value T, err error) {
	// Fork off a goroutine to wait for cancellation and wake up.
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() {
		<-ctx.Done()
		p.cond.Broadcast()
	}()

	p.Lock()
	defer p.Unlock()

	// Wait until the promise is resolved or context cancelled.
	for p.state == promiseUnresolved && (ctx == nil || ctx.Err() == nil) {
		p.cond.Wait()
	}

	if ctx.Err() != nil {
		err = ctx.Err()
	} else if p.state == promiseResolved {
		value = p.value
	} else {
		err = p.err
	}
	return
}

type wrappedPromise[T any] func(context.Context) (T, error)

func (await wrappedPromise[T]) Await(ctx context.Context) (T, error) {
	return await(ctx)
}

// Map transforms the value of a promise with the provided function.
func Map[A, B any](p Promise[A], transform func(A) B) Promise[B] {
	return wrappedPromise[B](func(ctx context.Context) (out B, err error) {
		v, err := p.Await(ctx)
		if err != nil {
			return out, err
		}
		return transform(v), nil
	})
}

// MapError transforms the error of a rejected promise with the provided function.
func MapError[A any](p Promise[A], transform func(error) error) Promise[A] {
	return wrappedPromise[A](func(ctx context.Context) (out A, err error) {
		v, err := p.Await(ctx)
		if err != nil {
			err = transform(err)
		}
		return v, err
	})
}
