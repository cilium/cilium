/*
Copyright 2018 The Kubernetes Authors.

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

package handler

import (
	"context"

	"k8s.io/client-go/util/workqueue"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

// MapFunc is the signature required for enqueueing requests from a generic function.
// This type is usually used with EnqueueRequestsFromMapFunc when registering an event handler.
type MapFunc = TypedMapFunc[client.Object]

// TypedMapFunc is the signature required for enqueueing requests from a generic function.
// This type is usually used with EnqueueRequestsFromTypedMapFunc when registering an event handler.
//
// TypedMapFunc is experimental and subject to future change.
type TypedMapFunc[T any] func(context.Context, T) []reconcile.Request

// EnqueueRequestsFromMapFunc enqueues Requests by running a transformation function that outputs a collection
// of reconcile.Requests on each Event.  The reconcile.Requests may be for an arbitrary set of objects
// defined by some user specified transformation of the source Event.  (e.g. trigger Reconciler for a set of objects
// in response to a cluster resize event caused by adding or deleting a Node)
//
// EnqueueRequestsFromMapFunc is frequently used to fan-out updates from one object to one or more other
// objects of a differing type.
//
// For UpdateEvents which contain both a new and old object, the transformation function is run on both
// objects and both sets of Requests are enqueue.
func EnqueueRequestsFromMapFunc(fn MapFunc) EventHandler {
	return TypedEnqueueRequestsFromMapFunc(fn)
}

// TypedEnqueueRequestsFromMapFunc enqueues Requests by running a transformation function that outputs a collection
// of reconcile.Requests on each Event.  The reconcile.Requests may be for an arbitrary set of objects
// defined by some user specified transformation of the source Event.  (e.g. trigger Reconciler for a set of objects
// in response to a cluster resize event caused by adding or deleting a Node)
//
// TypedEnqueueRequestsFromMapFunc is frequently used to fan-out updates from one object to one or more other
// objects of a differing type.
//
// For TypedUpdateEvents which contain both a new and old object, the transformation function is run on both
// objects and both sets of Requests are enqueue.
//
// TypedEnqueueRequestsFromMapFunc is experimental and subject to future change.
func TypedEnqueueRequestsFromMapFunc[T any](fn TypedMapFunc[T]) TypedEventHandler[T] {
	return &enqueueRequestsFromMapFunc[T]{
		toRequests: fn,
	}
}

var _ EventHandler = &enqueueRequestsFromMapFunc[client.Object]{}

type enqueueRequestsFromMapFunc[T any] struct {
	// Mapper transforms the argument into a slice of keys to be reconciled
	toRequests TypedMapFunc[T]
}

// Create implements EventHandler.
func (e *enqueueRequestsFromMapFunc[T]) Create(ctx context.Context, evt event.TypedCreateEvent[T], q workqueue.RateLimitingInterface) {
	reqs := map[reconcile.Request]empty{}
	e.mapAndEnqueue(ctx, q, evt.Object, reqs)
}

// Update implements EventHandler.
func (e *enqueueRequestsFromMapFunc[T]) Update(ctx context.Context, evt event.TypedUpdateEvent[T], q workqueue.RateLimitingInterface) {
	reqs := map[reconcile.Request]empty{}
	e.mapAndEnqueue(ctx, q, evt.ObjectOld, reqs)
	e.mapAndEnqueue(ctx, q, evt.ObjectNew, reqs)
}

// Delete implements EventHandler.
func (e *enqueueRequestsFromMapFunc[T]) Delete(ctx context.Context, evt event.TypedDeleteEvent[T], q workqueue.RateLimitingInterface) {
	reqs := map[reconcile.Request]empty{}
	e.mapAndEnqueue(ctx, q, evt.Object, reqs)
}

// Generic implements EventHandler.
func (e *enqueueRequestsFromMapFunc[T]) Generic(ctx context.Context, evt event.TypedGenericEvent[T], q workqueue.RateLimitingInterface) {
	reqs := map[reconcile.Request]empty{}
	e.mapAndEnqueue(ctx, q, evt.Object, reqs)
}

func (e *enqueueRequestsFromMapFunc[T]) mapAndEnqueue(ctx context.Context, q workqueue.RateLimitingInterface, object T, reqs map[reconcile.Request]empty) {
	for _, req := range e.toRequests(ctx, object) {
		_, ok := reqs[req]
		if !ok {
			q.Add(req)
			reqs[req] = empty{}
		}
	}
}
