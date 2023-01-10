// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package serializer

type FunctionQueue struct {
	queue  chan func() error
	stopCh chan struct{}
	err    error
}

// NewFunctionQueue returns a FunctionQueue that will be used to execute
// functions in the same order they are enqueued.
func NewFunctionQueue() *FunctionQueue {
	fq := &FunctionQueue{
		queue:  make(chan func() error),
		stopCh: make(chan struct{}),
	}
	go fq.run()
	return fq
}

// run the queue's internal worker. Returns when stopCh is closed or when
// a function has been dequeued and executed. Closes stopCh after invoking
// a function.
func (fq *FunctionQueue) run() {
	select {
	case f := <-fq.queue:
		fq.err = f()
		// Unblock all callers to Wait().
		close(fq.stopCh)
	case <-fq.stopCh:
		return
	}
}

// Wait for the queue to be stopped.
//
// Returns any error returned by an enqueued function.
func (fq *FunctionQueue) Wait() error {
	<-fq.stopCh
	return fq.err
}

// Enqueue f to the queue. Blocks if the queue is full.
// Returns immediately if the queue has been closed.
func (fq *FunctionQueue) Enqueue(f func() error) {
	select {
	case fq.queue <- f:
	case <-fq.stopCh:
	}
}
