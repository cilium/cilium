// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

// Package workerpool implements a concurrency limiting worker pool.
// Worker routines are spawned on demand as tasks are submitted; up to the
// configured limit of concurrent workers.
//
// When the limit of concurrently running workers is reached, submitting a task
// blocks until a worker is able to pick it up. This behavior is intentional as
// it prevents from accumulating tasks which could grow unbounded. Therefore,
// it is the responsibility of the caller to queue up tasks if that's the
// intended behavior.
//
// One caveat is that while the number of concurrently running workers is
// limited, task results are not and they accumulate until they are collected.
// Therefore, if a large number of tasks can be expected, the workerpool should
// be periodically drained (e.g. every 10k tasks).
// Alternatively, use [WithResultCallback] to process results as they complete
// without accumulation.
package workerpool

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"
)

var (
	// ErrDraining is returned when an operation is not possible because
	// draining is in progress.
	ErrDraining = errors.New("drain operation in progress")
	// ErrClosed is returned when operations are attempted after a call to [Close].
	ErrClosed = errors.New("worker pool is closed")
	// ErrCallbackSet is returned by [Drain] when a result callback has been
	// registered via [WithResultCallback].
	ErrCallbackSet = errors.New("a result callback is set")
)

// Option configures a WorkerPool.
type Option func(*WorkerPool)

// WithResultCallback registers fn to be called each time a task completes.
//
// When a callback is set, results are NOT accumulated internally. This
// means:
//   - [Drain] will return [ErrCallbackSet] instead of collecting results
//   - Results are processed immediately upon completion, avoiding memory
//     buildup
//
// The callback fn is invoked from the worker goroutines.
// This has a few implications:
// 1. fn must be safe for concurrent use.
// 2. fn must NOT call [Submit] nor [Close] as it will lead to a deadlock.
//
// WithResultCallback panics if fn is nil.
func WithResultCallback(fn func(Result)) Option {
	// TODO(v2): New/NewWithContext should return an error so that option
	// validation can propagate errors instead of panicking.
	if fn == nil {
		panic("workerpool.WithResultCallback: fn must not be nil")
	}
	return func(wp *WorkerPool) {
		wp.onResult = fn
	}
}

// WorkerPool spawns, on demand, a number of worker routines to process
// submitted tasks concurrently. The number of concurrent routines never
// exceeds the specified limit.
type WorkerPool struct {
	workers  chan struct{}
	tasks    chan *task
	done     <-chan struct{}
	cancel   context.CancelFunc
	onResult func(Result)
	results  []Task
	wg       sync.WaitGroup

	mu       sync.Mutex
	draining bool
	closed   bool
}

// New creates a new pool of workers where at most n workers process submitted
// tasks concurrently. New panics if n ≤ 0.
func New(n int, opts ...Option) *WorkerPool {
	return NewWithContext(context.Background(), n, opts...)
}

// NewWithContext creates a new pool of workers where at most n workers
// process submitted tasks concurrently. NewWithContext panics if n ≤ 0. The
// context is used as the parent context to the context of the task func passed
// to [Submit].
func NewWithContext(ctx context.Context, n int, opts ...Option) *WorkerPool {
	if n <= 0 {
		panic(fmt.Sprintf("workerpool.New: n must be > 0, got %d", n))
	}
	wp := &WorkerPool{
		workers: make(chan struct{}, n),
		tasks:   make(chan *task),
	}
	ctx, cancel := context.WithCancel(ctx)
	wp.cancel = cancel
	wp.done = ctx.Done()
	for _, opt := range opts {
		opt(wp)
	}
	go wp.run(ctx)
	return wp
}

// Cap returns the concurrent workers capacity, see [New].
func (wp *WorkerPool) Cap() int {
	return cap(wp.workers)
}

// Len returns the count of concurrent workers currently running.
func (wp *WorkerPool) Len() int {
	return len(wp.workers)
}

// Submit submits f for processing by a worker. The given id is useful for
// identifying the task once it is completed.
//
// The task function f receives a context that is cancelled when [Close] is
// called or when the parent context passed to [NewWithContext] is done. Tasks
// MUST respect context cancellation and return promptly when ctx.Done() is
// signaled. Tasks that ignore cancellation will cause [Close] to block
// indefinitely waiting for them to complete. Use context-aware operations
// (e.g., select with ctx.Done()) to ensure timely shutdown.
//
// Submit blocks until a routine starts processing the task.
//
// [ErrDraining] is returned if a drain operation is in progress.
// [ErrClosed] is returned if the worker pool is closed.
// [context.Canceled] is returned if the parent context is done.
func (wp *WorkerPool) Submit(id string, f func(ctx context.Context) error) error {
	wp.mu.Lock()
	if wp.closed {
		wp.mu.Unlock()
		return ErrClosed
	}
	if wp.draining {
		wp.mu.Unlock()
		return ErrDraining
	}
	select {
	case <-wp.done:
		wp.mu.Unlock()
		return context.Canceled
	default:
	}
	wp.wg.Add(1)
	wp.mu.Unlock()
	wp.tasks <- &task{
		id:  id,
		run: f,
	}
	return nil
}

// Drain waits until all tasks are completed. This operation prevents
// submitting new tasks to the worker pool. Drain returns the results of the
// tasks that have been processed.
//
// Drain is incompatible with the [WithResultCallback] option. When a result
// callback is configured, results are processed immediately upon completion
// rather than being accumulated, so Drain returns [ErrCallbackSet].
//
// Unlike [Close], Drain does not cancel task contexts. Tasks run to completion
// naturally. After Drain, the pool can be closed with [Close] (which will not
// cancel any tasks since none are running) or more tasks can be submitted.
//
// [ErrCallbackSet] is returned if the [WithResultCallback] option is used.
// [ErrDraining] is returned if a drain operation is already in progress.
// [ErrClosed] is returned if the worker pool is closed.
func (wp *WorkerPool) Drain() ([]Task, error) {
	wp.mu.Lock()
	if wp.closed {
		wp.mu.Unlock()
		return nil, ErrClosed
	}
	if wp.draining {
		wp.mu.Unlock()
		return nil, ErrDraining
	}
	// TODO(v2): remove ErrCallbackSet — a pool configured with WithResultCallback should not expose Drain.
	if wp.onResult != nil {
		wp.mu.Unlock()
		return nil, ErrCallbackSet
	}
	wp.draining = true
	wp.mu.Unlock()

	wp.wg.Wait()

	// NOTE: No lock is needed here due to the following synchronization:
	// 1. Only the single run() goroutine writes to wp.results.
	// 2. run() appends each result BEFORE spawning its worker goroutine.
	// 3. Each worker calls wg.Done() upon completion.
	// 4. wg.Wait() above ensures all workers (and thus all appends) completed.
	// 5. run() is now blocked waiting for tasks on the channel.
	// Therefore, no concurrent access to wp.results is possible here.
	res := wp.results
	wp.results = nil

	wp.mu.Lock()
	wp.draining = false
	wp.mu.Unlock()

	return res, nil
}

// Close closes the worker pool, rendering it unable to process new tasks.
// Close sends the cancellation signal to any running task via context
// cancellation and waits indefinitely for all workers to return. If tasks do
// not respect context cancellation, Close will block until they complete.
// When a result callback is set via [WithResultCallback], all callback
// invocations are guaranteed to have completed before Close returns.
//
// Close will return [ErrClosed] if it has already been called. This makes
// it safe to use with defer immediately after creating the pool (for
// cleanup on early returns) while still calling Close explicitly to check
// for errors.
//
// Note: Close cancels running tasks via context, while [Drain] waits for
// tasks to complete without cancellation. If you want tasks to finish
// naturally, call [Drain] before Close.
func (wp *WorkerPool) Close() error {
	wp.mu.Lock()
	if wp.closed {
		wp.mu.Unlock()
		return ErrClosed
	}
	wp.closed = true
	wp.mu.Unlock()

	wp.cancel()
	wp.wg.Wait()

	// At this point, all routines have returned. This means that Submit is not
	// pending to write to the task channel and it is thus safe to close it.
	close(wp.tasks)

	// wait for the "run" routine
	<-wp.workers
	return nil
}

// run loops over the tasks channel and starts processing routines. It should
// only be called once during the lifetime of a WorkerPool.
// This is the sole goroutine that writes to wp.results, making it safe to
// append without a lock. The append happens before spawning each worker,
// establishing a happens-before relationship that ensures [Drain] can safely
// read wp.results after wg.Wait() completes.
func (wp *WorkerPool) run(ctx context.Context) {
	for t := range wp.tasks {
		result := taskResult{id: t.id}
		if wp.onResult == nil {
			wp.results = append(wp.results, &result)
		}
		wp.workers <- struct{}{}
		go func() {
			defer wp.wg.Done()
			start := time.Now()
			if t.run != nil {
				result.err = t.run(ctx)
			}
			result.duration = time.Since(start)
			if wp.onResult != nil {
				wp.onResult(&result)
			}
			<-wp.workers
		}()
	}
	close(wp.workers)
}
