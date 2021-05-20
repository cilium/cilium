// Copyright 2021 Authors of Cilium
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

// Package workerpool implements a concurrency limiting worker pool.
// Worker routines are spawned on demand as tasks are submitted.
package workerpool

import (
	"context"
	"errors"
	"fmt"
	"sync"
)

var (
	// ErrDraining is returned when an operation is not possible because
	// draining is in progress.
	ErrDraining = errors.New("drain operation in progress")
	// ErrClosed is returned when operations are attempted after a call to Close.
	ErrClosed = errors.New("worker pool is closed")
)

// WorkerPool spawns, on demand, a number of worker routines to process
// submitted tasks concurrently. The number of concurrent routines never
// exceeds the specified limit.
type WorkerPool struct {
	workers  chan struct{}
	tasks    chan *task
	results  []Task
	wg       sync.WaitGroup
	mu       sync.Mutex
	draining bool
	cancel   context.CancelFunc
	closed   bool
}

// New creates a new pool of workers where at most n workers process submitted
// tasks concurrently. New panics if n ≤ 0.
func New(n int) *WorkerPool {
	if n <= 0 {
		panic(fmt.Sprintf("workerpool.New: n must be > 0, got %d", n))
	}
	wp := &WorkerPool{
		workers: make(chan struct{}, n),
		tasks:   make(chan *task),
	}
	ctx, cancel := context.WithCancel(context.Background())
	wp.cancel = cancel
	go wp.run(ctx)
	return wp
}

// Cap returns the concurrent workers capacity, see New().
func (wp *WorkerPool) Cap() int {
	return cap(wp.workers)
}

// Submit submits f for processing by a worker. The given id is useful for
// identifying the task once it is completed. The task f must return when the
// context ctx is cancelled.
//
// Submit blocks until a routine start processing the task.
//
// If a drain operation is in progress, ErrDraining is returned and the task
// is not submitted for processing.
// If the worker pool is closed, ErrClosed is returned and the task is not
// submitted for processing.
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

	wp.mu.Unlock()
	wp.wg.Add(1)
	wp.tasks <- &task{
		id:  id,
		run: f,
	}
	return nil
}

// Drain waits until all tasks are completed. This operation prevents
// submitting new tasks to the worker pool. Drain returns the results of the
// tasks that have been processed.
// If a drain operation is already in progress, ErrDraining is returned.
// If the worker pool is closed, ErrClosed is returned and the task is not
// submitted for processing.
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
	wp.draining = true
	wp.mu.Unlock()

	wp.wg.Wait()

	// NOTE: It's not necessary to hold a lock when reading or writing
	// wp.results as no other routine is running at this point besides the
	// "run" routine which should be waiting on the tasks channel.
	res := wp.results
	wp.results = nil

	wp.mu.Lock()
	wp.draining = false
	wp.mu.Unlock()

	return res, nil
}

// Close closes the worker pool, rendering it unable to process new tasks.
// Close sends the cancellation signal to any running task and waits for all
// workers, if any, to return.
// Close will return ErrClosed if it has already been called.
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
func (wp *WorkerPool) run(ctx context.Context) {
	for t := range wp.tasks {
		t := t
		wp.results = append(wp.results, t)
		wp.workers <- struct{}{}
		go func() {
			defer wp.wg.Done()
			t.err = t.run(ctx)
			<-wp.workers
		}()
	}
	close(wp.workers)
}
