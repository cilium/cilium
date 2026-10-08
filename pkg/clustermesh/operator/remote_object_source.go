// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package operator

import (
	"context"

	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/workqueue"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/source"

	"github.com/cilium/cilium/pkg/lock"
)

type NamespacedNamed interface {
	NamespacedName() types.NamespacedName
}

// NewEnqueueRequestForNamespacedNameFunc returns a simple handler that
// enqueues a reconcile request with the object namespaced name.
func NewEnqueueRequestForNamespacedNameFunc[T NamespacedNamed]() handler.TypedEventHandler[T, ctrl.Request] {
	return handler.TypedEnqueueRequestsFromMapFunc(
		func(ctx context.Context, obj T) []ctrl.Request {
			return []ctrl.Request{{NamespacedName: obj.NamespacedName()}}
		},
	)
}

var _ source.Source = &RemoteObjectSource[any]{}

type remoteObjectEvent[T any] func(
	ctx context.Context, handler handler.TypedEventHandler[T, ctrl.Request],
	queue workqueue.TypedRateLimitingInterface[ctrl.Request],
)

// RemoteObjectSource bridges remote clustermesh object events into
// controller-runtime reconcile requests.
type RemoteObjectSource[T any] struct {
	handler handler.TypedEventHandler[T, ctrl.Request]

	mutex lock.Mutex
	buf   []remoteObjectEvent[T]
	ctx   context.Context
	queue workqueue.TypedRateLimitingInterface[ctrl.Request]
}

// NewRemoteObjectSource creates a controller-runtime source for remote
// clustermesh object events.
func NewRemoteObjectSource[T any](
	handler handler.TypedEventHandler[T, ctrl.Request],
) *RemoteObjectSource[T] {
	return &RemoteObjectSource[T]{
		handler: handler,
	}
}

func (s *RemoteObjectSource[T]) OnEvent(obj T) {
	s.enqueue(func(
		ctx context.Context, handler handler.TypedEventHandler[T, ctrl.Request],
		queue workqueue.TypedRateLimitingInterface[ctrl.Request],
	) {
		evt := event.TypedGenericEvent[T]{Object: obj}
		handler.Generic(ctx, evt, queue)
	})
}

func (s *RemoteObjectSource[T]) enqueue(evt remoteObjectEvent[T]) {
	s.mutex.Lock()
	if s.queue == nil {
		// Start was not called yet, buffer the event
		s.buf = append(s.buf, evt)
		s.mutex.Unlock()
		return
	}
	ctx := s.ctx
	queue := s.queue
	s.mutex.Unlock()

	evt(ctx, s.handler, queue)
}

func (s *RemoteObjectSource[T]) Start(
	ctx context.Context, queue workqueue.TypedRateLimitingInterface[ctrl.Request],
) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	s.ctx = ctx
	s.queue = queue
	for _, evt := range s.buf {
		// Queue the events that were received before Start was called
		evt(ctx, s.handler, s.queue)
	}
	s.buf = nil

	return nil
}
