// Copyright 2017-2019 Authors of Cilium
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

package serializer

import (
	"context"
	"fmt"
)

var (
	// NoRetry always returns false independently of the number of retries.
	NoRetry = func(int) bool { return false }
)

// WaitFunc will be invoked each time a queued function has returned an error.
// nRetries will be set to the number of consecutive execution failures that
// have occurred so far. The WaitFunc must return true if execution must be
// retried or false if the function must be returned from the queue.
type WaitFunc func(nRetries int) bool

type queuedFunction struct {
	f        func() error
	waitFunc WaitFunc
}

type FunctionQueue struct {
	queue  chan queuedFunction
	stopCh chan struct{}
}

// NewFunctionQueue returns a FunctionQueue that will be used to execute
// functions in the same order they are enqueued.
func NewFunctionQueue(queueSize uint) *FunctionQueue {
	fq := &FunctionQueue{
		queue:  make(chan queuedFunction, queueSize),
		stopCh: make(chan struct{}),
	}
	go fq.run()
	return fq
}

// run starts the FunctionQueue internal worker. It will be stopped once
// `stopCh` is closed or receives a value.
func (fq *FunctionQueue) run() {
	for {
		select {
		case <-fq.stopCh:
			return
		case f := <-fq.queue:
			retries := 0
			for {
				select {
				case <-fq.stopCh:
					return
				default:
				}
				retries++
				if err := f.f(); err != nil {
					if !f.waitFunc(retries) {
						break
					}
				} else {
					break
				}
			}
		}
	}
}

// Stop stops the function queue from processing the functions on the queue.
// If there are functions in the queue waiting for them to be processed, they
// won't be executed.
func (fq *FunctionQueue) Stop() {
	close(fq.stopCh)
}

// Wait until the FunctionQueue is stopped, or the specified context deadline
// expires. Returns the error from the context, or nil if the FunctionQueue
// was completed before the context deadline.
func (fq *FunctionQueue) Wait(ctx context.Context) error {
	select {
	case <-fq.stopCh:
	case <-ctx.Done():
	}
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("serializer %s", err)
	}
	return nil
}

// Enqueue enqueues the receiving function `f` to be executed by the function
// queue. Depending on the size of the function queue and the amount
// of functions queued, this function can block until the function queue
// is ready to receive more requests.
// If `f` returns an error, `waitFunc` will be executed and, depending on the
// return value of `waitFunc`, `f` will be executed again or not.
// The return value of `f` will not be logged and it's up to the caller to log
// it properly.
func (fq *FunctionQueue) Enqueue(f func() error, waitFunc WaitFunc) {
	fq.queue <- queuedFunction{f: f, waitFunc: waitFunc}
}
