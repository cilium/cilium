// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package hive

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/cilium/hive/cell"

	"github.com/cilium/cilium/pkg/lock"
)

// OnDemand provides access to a resource on-demand.
// On first call to Acquire() the resource is started (cell.Lifecycle.Start).
// If the starting of the resource fails Acquire() returns the error from Start().
// When all references are Release()'d the resource is stopped (cell.Lifecycle.Stop),
// and again failure from Stop() is returned.
type OnDemand[Resource any] interface {
	// Acquire a resource. On the first call to Acquire() the underlying
	// resource is started with the provided context that aborts the start
	// if the context is cancelled. On failure to start the resulting error
	// is returned.
	Acquire(context.Context) (Resource, error)

	// Release a resource. When the last acquired reference to the resource
	// is released the resource is stopped. If stopping the resource fails
	// the error is returned.
	Release(resource Resource) error
}

type onDemand[Resource any] struct {
	mu       lock.Mutex
	log      *slog.Logger
	refCount int
	resource Resource
	lc       cell.Lifecycle
}

// NewOnDemand wraps a resource that will be started and stopped on-demand.
// The resource and the lifecycle hooks are provided separately, but can
// of course be the same thing. They're separate to support the use-case
// where the resource is a state object (e.g. StateDB table) and the hook is
// a job group that populates the object.
func NewOnDemand[Resource any](log *slog.Logger, resource Resource, lc cell.Lifecycle) OnDemand[Resource] {
	return &onDemand[Resource]{
		log:      log,
		refCount: 0,
		resource: resource,
		lc:       lc,
	}
}

// Acquire implements OnDemand.
func (o *onDemand[Resource]) Acquire(ctx context.Context) (r Resource, err error) {
	o.mu.Lock()
	defer o.mu.Unlock()

	if o.refCount == 0 {
		// This is the first acquisition of the resource. Start it.
		if err = o.lc.Start(o.log, ctx); err != nil {
			return r, fmt.Errorf("failed to start resource %T: %w", r, err)
		}
	}

	o.refCount++
	return o.resource, nil
}

// Release implements OnDemand.
func (o *onDemand[Resource]) Release(r Resource) error {
	o.mu.Lock()
	defer o.mu.Unlock()

	if o.refCount <= 0 {
		return fmt.Errorf("BUG: OnDemand.Release called with refCount <= 0")
	}

	o.refCount--
	if o.refCount == 0 {
		if err := o.lc.Stop(o.log, context.Background()); err != nil {
			return fmt.Errorf("failed to stop resource %T: %w", r, err)
		}
	}
	return nil
}

var _ OnDemand[cell.Hook] = &onDemand[cell.Hook]{}

type staticOnDemand[Resource any] struct {
	resource Resource
}

// Acquire implements OnDemand.
func (s *staticOnDemand[Resource]) Acquire(context.Context) (Resource, error) {
	return s.resource, nil
}

// Release implements OnDemand.
func (s *staticOnDemand[Resource]) Release(Resource) error {
	return nil
}

var _ OnDemand[struct{}] = &staticOnDemand[struct{}]{}

// NewStaticOnDemand creates an on-demand resource that is "static",
// i.e. always running and not started or stopped.
func NewStaticOnDemand[Resource any](resource Resource) OnDemand[Resource] {
	return &staticOnDemand[Resource]{resource}
}
