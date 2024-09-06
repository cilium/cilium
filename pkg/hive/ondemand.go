// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package hive

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/hive/cell"
)

// OnDemand provides access to a resource on-demand.
// On first call to Acquire() the resource is started (cell.Lifecycle.Start).
// If the starting of the resource fails Acquire()

// and when all references are Release()'d the resource is stopped (cell.Lifecycle.Stop).
type OnDemand[Resource any] interface {
	// Acquire a resource. On the first call to Acquire() the underlying
	// resource is started with the provided context that aborts the start
	// if the context is cancelled. On failure to start the resulting error
	// is returned.
	Acquire(context.Context) (Resource, error)

	// Release a resource. When the last acquired reference to the resource
	// is released the resource is stopped.
	Release(resource Resource)
}

type staticOnDemand[Resource any] struct {
	resource Resource
}

// Acquire implements OnDemand.
func (s *staticOnDemand[Resource]) Acquire(context.Context) (Resource, error) {
	return s.resource, nil
}

// Release implements OnDemand.
func (s *staticOnDemand[Resource]) Release(Resource) {
}

var _ OnDemand[struct{}] = &staticOnDemand[struct{}]{}

func NewStaticOnDemand[Resource any](resource Resource) OnDemand[Resource] {
	return &staticOnDemand[Resource]{resource}
}

type onDemand[Resource any] struct {
	mu       lock.Mutex
	log      *slog.Logger
	refCount int
	resource Resource
	hook     cell.HookInterface
}

// NewOnDemand wraps a resource that will be started and stopped on-demand.
// The resource and the lifecycle hooks are provided separately, but can
// of course be the same thing. They're separate to support the use-case
// where the resource is a state object (e.g. StateDB table) and the hook is
// a job group that populates the object.
func NewOnDemand[Resource any](log *slog.Logger, resource Resource, hook cell.HookInterface) OnDemand[Resource] {
	return &onDemand[Resource]{
		log:      log,
		refCount: 0,
		resource: resource,
		hook:     hook,
	}
}

// Acquire implements OnDemand.
func (o *onDemand[Resource]) Acquire(ctx context.Context) (r Resource, err error) {
	o.mu.Lock()
	defer o.mu.Unlock()

	if o.refCount == 0 {
		// This is the first acquisition of the resource. Start it.
		err = o.hook.Start(ctx)
		if err != nil {
			return
		}
	}

	o.refCount++
	return o.resource, nil
}

// Release implements OnDemand.
func (o *onDemand[Resource]) Release(r Resource) {
	o.mu.Lock()
	defer o.mu.Unlock()

	if o.refCount == 0 {
		panic("BUG: Release(): refCount == 0")
	}

	o.refCount--
	if o.refCount == 0 {
		err := o.hook.Stop(context.Background())
		if err != nil {
			typ := fmt.Sprintf(`%T`, r)
			o.log.Error("Failed to stop resource", "type", typ)
		}
	}
}

var _ OnDemand[cell.Hook] = &onDemand[cell.Hook]{}
