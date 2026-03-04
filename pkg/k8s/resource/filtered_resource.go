// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package resource

import (
	"context"

	"github.com/cilium/stream"
	k8sRuntime "k8s.io/apimachinery/pkg/runtime"
)

// FilteredResource acts the same way as a Resource, but does not have access to the underlying store,
// as it should be constructed from the parent Resource.
type FilteredResource[T k8sRuntime.Object] interface {
	stream.Observable[Event[T]]
	Events(ctx context.Context, opts ...EventsOpt) <-chan Event[T]
}

// filteringResource wraps a Resource and filters the events based on the provided filter function.
type filteringResource[T k8sRuntime.Object] struct {
	parent Resource[T]
	filter func(T) bool
}

// NewFilteringResource creates a new FilteringResource.
func NewFilteringResource[T k8sRuntime.Object](parent Resource[T], filter func(T) bool) FilteredResource[T] {
	return &filteringResource[T]{
		parent: parent,
		filter: filter,
	}
}

// Events returns a channel of events for the filtered resource.
// It filters out events that do not match the filter function.
func (r *filteringResource[T]) Events(ctx context.Context, opts ...EventsOpt) <-chan Event[T] {
	out := make(chan Event[T])
	parentEvents := r.parent.Events(ctx, opts...)

	go func() {
		defer close(out)
		for ev := range parentEvents {
			if ev.Kind == Sync {
				out <- ev
				continue
			}

			if r.filter(ev.Object) {
				out <- ev
			} else {
				ev.Done(nil)
			}
		}
	}()

	return out
}

func (r *filteringResource[T]) Observe(ctx context.Context, next func(Event[T]), complete func(error)) {
	stream.FromChannel(r.Events(ctx)).Observe(ctx, next, complete)
}
