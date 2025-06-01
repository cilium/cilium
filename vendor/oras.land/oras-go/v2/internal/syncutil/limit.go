/*
Copyright The ORAS Authors.
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package syncutil

import (
	"context"

	"golang.org/x/sync/errgroup"
	"golang.org/x/sync/semaphore"
)

// LimitedRegion provides a way to bound concurrent access to a code block.
type LimitedRegion struct {
	ctx     context.Context
	limiter *semaphore.Weighted
	ended   bool
}

// LimitRegion creates a new LimitedRegion.
func LimitRegion(ctx context.Context, limiter *semaphore.Weighted) *LimitedRegion {
	if limiter == nil {
		return nil
	}
	return &LimitedRegion{
		ctx:     ctx,
		limiter: limiter,
		ended:   true,
	}
}

// Start starts the region with concurrency limit.
func (lr *LimitedRegion) Start() error {
	if lr == nil || !lr.ended {
		return nil
	}
	if err := lr.limiter.Acquire(lr.ctx, 1); err != nil {
		return err
	}
	lr.ended = false
	return nil
}

// End ends the region with concurrency limit.
func (lr *LimitedRegion) End() {
	if lr == nil || lr.ended {
		return
	}
	lr.limiter.Release(1)
	lr.ended = true
}

// GoFunc represents a function that can be invoked by Go.
type GoFunc[T any] func(ctx context.Context, region *LimitedRegion, t T) error

// Go concurrently invokes fn on items.
func Go[T any](ctx context.Context, limiter *semaphore.Weighted, fn GoFunc[T], items ...T) error {
	eg, egCtx := errgroup.WithContext(ctx)
	for _, item := range items {
		region := LimitRegion(ctx, limiter)
		if err := region.Start(); err != nil {
			return err
		}
		eg.Go(func(t T) func() error {
			return func() error {
				defer region.End()
				return fn(egCtx, region, t)
			}
		}(item))
	}
	return eg.Wait()
}
