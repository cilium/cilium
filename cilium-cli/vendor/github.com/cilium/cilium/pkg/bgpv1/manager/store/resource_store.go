// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package store

import (
	"context"
	"fmt"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	k8sRuntime "k8s.io/apimachinery/pkg/runtime"

	"github.com/cilium/cilium/pkg/bgpv1/agent/signaler"
	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/time"
)

// BGPCPResourceStore is a wrapper around the resource.Store for the BGP Control Plane reconcilers usage.
// It automatically signals the BGP Control Plane whenever an event happens on the resource.
type BGPCPResourceStore[T k8sRuntime.Object] interface {
	// GetByKey returns the latest version of the object with given key.
	GetByKey(key resource.Key) (item T, exists bool, err error)

	// List returns all items currently in the store.
	List() (items []T, err error)
}

var _ BGPCPResourceStore[*k8sRuntime.Unknown] = (*bgpCPResourceStore[*k8sRuntime.Unknown])(nil)

type bgpCPResourceStoreParams[T k8sRuntime.Object] struct {
	cell.In

	Lifecycle cell.Lifecycle
	Health    cell.Health
	JobGroup  job.Group
	Resource  resource.Resource[T]
	Signaler  *signaler.BGPCPSignaler
}

// bgpCPResourceStore takes a resource.Resource[T] and watches for events. It can still be used as a normal Store,
// but in addition to that it will signal the BGP Control plane upon each event via the passed BGPCPSignaler.
type bgpCPResourceStore[T k8sRuntime.Object] struct {
	store resource.Store[T]

	resource resource.Resource[T]
	signaler *signaler.BGPCPSignaler

	mu lock.Mutex
}

func NewBGPCPResourceStore[T k8sRuntime.Object](params bgpCPResourceStoreParams[T]) BGPCPResourceStore[T] {
	if params.Resource == nil {
		return nil
	}

	s := &bgpCPResourceStore[T]{
		resource: params.Resource,
		signaler: params.Signaler,
	}

	params.JobGroup.Add(
		job.OneShot("bgpcp-resource-store-events",
			func(ctx context.Context, health cell.Health) (err error) {
				s.store, err = s.resource.Store(ctx)
				if err != nil {
					return fmt.Errorf("error creating resource store: %w", err)
				}
				for event := range s.resource.Events(ctx) {
					s.signaler.Event(struct{}{})
					event.Done(nil)
				}
				return nil
			},
			job.WithRetry(3, &job.ExponentialBackoff{Min: 100 * time.Millisecond, Max: time.Second}),
			job.WithShutdown()),
	)

	return s
}

// List returns all items currently in the store.
func (s *bgpCPResourceStore[T]) List() (items []T, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.store == nil {
		return nil, ErrStoreUninitialized
	}

	return s.store.List(), nil
}

// GetByKey returns the latest version of the object with given key.
func (s *bgpCPResourceStore[T]) GetByKey(key resource.Key) (item T, exists bool, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.store == nil {
		var empty T
		return empty, false, ErrStoreUninitialized
	}

	return s.store.GetByKey(key)
}
