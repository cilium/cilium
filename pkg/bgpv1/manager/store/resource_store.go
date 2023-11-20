// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package store

import (
	"context"
	"fmt"

	"github.com/cilium/cilium/pkg/bgpv1/agent/signaler"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/k8s/resource"

	k8sRuntime "k8s.io/apimachinery/pkg/runtime"
)

// BGPCPResourceStore is a super set of the resource.Store for the BGP Control Plane reconcilers usage.
// It automatically signals the BGP Control Plane whenever an event happens on the resource.
type BGPCPResourceStore[T k8sRuntime.Object] interface {
	resource.Store[T]
}

var _ BGPCPResourceStore[*k8sRuntime.Unknown] = (*bgpCPResourceStore[*k8sRuntime.Unknown])(nil)

type bgpCPResourceStoreParams[T k8sRuntime.Object] struct {
	cell.In

	Lifecycle hive.Lifecycle
	Resource  resource.Resource[T]
	Signaler  *signaler.BGPCPSignaler
}

// bgpCPResourceStore takes a resource.Resource[T] and watches for events. It can still be used as a normal Store,
// but in addition to that it will signal the BGP Control plane upon each event via the passed BGPCPSignaler.
type bgpCPResourceStore[T k8sRuntime.Object] struct {
	resource.Store[T]

	resource resource.Resource[T]
	signaler *signaler.BGPCPSignaler

	ctx      context.Context
	cancel   context.CancelFunc
	doneChan chan struct{}
}

func NewBGPCPResourceStore[T k8sRuntime.Object](params bgpCPResourceStoreParams[T]) BGPCPResourceStore[T] {
	if params.Resource == nil {
		return nil
	}

	s := &bgpCPResourceStore[T]{
		resource: params.Resource,
		signaler: params.Signaler,
		doneChan: make(chan struct{}),
	}
	s.ctx, s.cancel = context.WithCancel(context.Background())

	params.Lifecycle.Append(s)

	return s
}

// Start implements hive.HookInterface
func (s *bgpCPResourceStore[T]) Start(ctx hive.HookContext) error {
	var err error
	s.Store, err = s.resource.Store(ctx)
	if err != nil {
		return fmt.Errorf("resource.Store(): %w", err)
	}

	go s.run()
	return nil
}

// Stop implements hive.HookInterface
func (s *bgpCPResourceStore[T]) Stop(stopCtx hive.HookContext) error {
	s.cancel()

	select {
	case <-s.doneChan:
	case <-stopCtx.Done():
		return stopCtx.Err()
	}

	return nil
}

func (s *bgpCPResourceStore[T]) run() {
	defer close(s.doneChan)

	for event := range s.resource.Events(s.ctx) {
		s.signaler.Event(struct{}{})
		event.Done(nil)
	}
}
