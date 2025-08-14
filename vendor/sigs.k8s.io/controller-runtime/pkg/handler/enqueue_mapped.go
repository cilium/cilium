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
	"sigs.k8s.io/controller-runtime/pkg/controller/priorityqueue"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

// MapFunc is the signature required for enqueueing requests from a generic function.
// This type is usually used with EnqueueRequestsFromMapFunc when registering an event handler.
type MapFunc = TypedMapFunc[client.Object, reconcile.Request]

// TypedMapFunc is the signature required for enqueueing requests from a generic function.
// This type is usually used with EnqueueRequestsFromTypedMapFunc when registering an event handler.
//
// TypedMapFunc is experimental and subject to future change.
type TypedMapFunc[object any, request comparable] func(context.Context, object) []request

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
func TypedEnqueueRequestsFromMapFunc[object any, request comparable](fn TypedMapFunc[object, request]) TypedEventHandler[object, request] {
	return &enqueueRequestsFromMapFunc[object, request]{
		toRequests:                   fn,
		objectImplementsClientObject: implementsClientObject[object](),
	}
}

var _ EventHandler = &enqueueRequestsFromMapFunc[client.Object, reconcile.Request]{}

type enqueueRequestsFromMapFunc[object any, request comparable] struct {
	// Mapper transforms the argument into a slice of keys to be reconciled
	toRequests                   TypedMapFunc[object, request]
	objectImplementsClientObject bool
}

// Create implements EventHandler.
func (e *enqueueRequestsFromMapFunc[object, request]) Create(
	ctx context.Context,
	evt event.TypedCreateEvent[object],
	q workqueue.TypedRateLimitingInterface[request],
) {
	reqs := map[request]empty{}

	var lowPriority bool
	if e.objectImplementsClientObject && isPriorityQueue(q) && !isNil(evt.Object) {
		clientObjectEvent := event.CreateEvent{Object: any(evt.Object).(client.Object)}
		if isObjectUnchanged(clientObjectEvent) {
			lowPriority = true
		}
	}
	e.mapAndEnqueue(ctx, q, evt.Object, reqs, lowPriority)
}

// Update implements EventHandler.
func (e *enqueueRequestsFromMapFunc[object, request]) Update(
	ctx context.Context,
	evt event.TypedUpdateEvent[object],
	q workqueue.TypedRateLimitingInterface[request],
) {
	var lowPriority bool
	if e.objectImplementsClientObject && isPriorityQueue(q) && !isNil(evt.ObjectOld) && !isNil(evt.ObjectNew) {
		lowPriority = any(evt.ObjectOld).(client.Object).GetResourceVersion() == any(evt.ObjectNew).(client.Object).GetResourceVersion()
	}
	reqs := map[request]empty{}
	e.mapAndEnqueue(ctx, q, evt.ObjectOld, reqs, lowPriority)
	e.mapAndEnqueue(ctx, q, evt.ObjectNew, reqs, lowPriority)
}

// Delete implements EventHandler.
func (e *enqueueRequestsFromMapFunc[object, request]) Delete(
	ctx context.Context,
	evt event.TypedDeleteEvent[object],
	q workqueue.TypedRateLimitingInterface[request],
) {
	reqs := map[request]empty{}
	e.mapAndEnqueue(ctx, q, evt.Object, reqs, false)
}

// Generic implements EventHandler.
func (e *enqueueRequestsFromMapFunc[object, request]) Generic(
	ctx context.Context,
	evt event.TypedGenericEvent[object],
	q workqueue.TypedRateLimitingInterface[request],
) {
	reqs := map[request]empty{}
	e.mapAndEnqueue(ctx, q, evt.Object, reqs, false)
}

func (e *enqueueRequestsFromMapFunc[object, request]) mapAndEnqueue(
	ctx context.Context,
	q workqueue.TypedRateLimitingInterface[request],
	o object,
	reqs map[request]empty,
	lowPriority bool,
) {
	for _, req := range e.toRequests(ctx, o) {
		_, ok := reqs[req]
		if !ok {
			if lowPriority {
				q.(priorityqueue.PriorityQueue[request]).AddWithOpts(priorityqueue.AddOpts{
					Priority: LowPriority,
				}, req)
			} else {
				q.Add(req)
			}
			reqs[req] = empty{}
		}
	}
}
