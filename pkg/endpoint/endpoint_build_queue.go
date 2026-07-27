// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package endpoint

import (
	"context"
	"runtime"
	"sync"

	"golang.org/x/sync/semaphore"
)

type EndpointBuildQueue interface {
	QueueEndpointBuild(ctx context.Context, epID uint64) (func(), error)
}

type endpointBuildQueue struct {
	buildEndpointSem *semaphore.Weighted
}

func NewEndpointBuildQueue() EndpointBuildQueue {
	return &endpointBuildQueue{
		buildEndpointSem: semaphore.NewWeighted(int64(numWorkerThreads())),
	}
}

// QueueEndpointBuild waits for a "build permit" for the endpoint
// identified by 'epID'. This function blocks until the endpoint can
// start building.  The returned function must then be called to
// release the "build permit" when the most resource intensive parts
// of the build are done. The returned function is idempotent, so it
// may be called more than once. Returns a nil function if the caller should NOT
// start building the endpoint. This may happen due to a build being
// queued for the endpoint already, or due to the wait for the build
// permit being canceled. The latter case happens when the endpoint is
// being deleted. Returns an error if the build permit could not be acquired.
func (q *endpointBuildQueue) QueueEndpointBuild(ctx context.Context, epID uint64) (func(), error) {
	// Acquire build permit. This may block.
	err := q.buildEndpointSem.Acquire(ctx, 1)
	if err != nil {
		return nil, err // Acquire failed
	}

	// Acquire succeeded, but the context was canceled after?
	if ctx.Err() != nil {
		q.buildEndpointSem.Release(1)
		return nil, ctx.Err()
	}

	// At this point the build permit has been acquired. It must
	// be released by the caller by calling the returned function
	// when the heavy lifting of the build is done.
	// Using sync.Once to make the returned function idempotent.
	var once sync.Once
	doneFunc := func() {
		once.Do(func() {
			q.buildEndpointSem.Release(1)
		})
	}
	return doneFunc, nil
}

// numWorkerThreads returns the number of worker threads with a minimum of 2.
func numWorkerThreads() int {
	ncpu := runtime.NumCPU()
	minWorkerThreads := 2

	if ncpu < minWorkerThreads {
		return minWorkerThreads
	}
	return ncpu
}

type MockEndpointBuildQueue struct{}

var _ EndpointBuildQueue = &MockEndpointBuildQueue{}

func (m *MockEndpointBuildQueue) QueueEndpointBuild(ctx context.Context, epID uint64) (func(), error) {
	return nil, nil
}
