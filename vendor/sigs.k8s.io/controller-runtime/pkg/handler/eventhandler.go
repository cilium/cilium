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
	"time"

	"k8s.io/client-go/util/workqueue"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/priorityqueue"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

// EventHandler enqueues reconcile.Requests in response to events (e.g. Pod Create).  EventHandlers map an Event
// for one object to trigger Reconciles for either the same object or different objects - e.g. if there is an
// Event for object with type Foo (using source.Kind) then reconcile one or more object(s) with type Bar.
//
// Identical reconcile.Requests will be batched together through the queuing mechanism before reconcile is called.
//
// * Use EnqueueRequestForObject to reconcile the object the event is for
// - do this for events for the type the Controller Reconciles. (e.g. Deployment for a Deployment Controller)
//
// * Use EnqueueRequestForOwner to reconcile the owner of the object the event is for
// - do this for events for the types the Controller creates.  (e.g. ReplicaSets created by a Deployment Controller)
//
// * Use EnqueueRequestsFromMapFunc to transform an event for an object to a reconcile of an object
// of a different type - do this for events for types the Controller may be interested in, but doesn't create.
// (e.g. If Foo responds to cluster size events, map Node events to Foo objects.)
//
// Unless you are implementing your own EventHandler, you can ignore the functions on the EventHandler interface.
// Most users shouldn't need to implement their own EventHandler.
type EventHandler = TypedEventHandler[client.Object, reconcile.Request]

// TypedEventHandler enqueues reconcile.Requests in response to events (e.g. Pod Create). TypedEventHandlers map an Event
// for one object to trigger Reconciles for either the same object or different objects - e.g. if there is an
// Event for object with type Foo (using source.Kind) then reconcile one or more object(s) with type Bar.
//
// Identical reconcile.Requests will be batched together through the queuing mechanism before reconcile is called.
//
// * Use TypedEnqueueRequestForObject to reconcile the object the event is for
// - do this for events for the type the Controller Reconciles. (e.g. Deployment for a Deployment Controller)
//
// * Use TypedEnqueueRequestForOwner to reconcile the owner of the object the event is for
// - do this for events for the types the Controller creates.  (e.g. ReplicaSets created by a Deployment Controller)
//
// * Use TypedEnqueueRequestsFromMapFunc to transform an event for an object to a reconcile of an object
// of a different type - do this for events for types the Controller may be interested in, but doesn't create.
// (e.g. If Foo responds to cluster size events, map Node events to Foo objects.)
//
// Unless you are implementing your own TypedEventHandler, you can ignore the functions on the TypedEventHandler interface.
// Most users shouldn't need to implement their own TypedEventHandler.
//
// TypedEventHandler is experimental and subject to future change.
type TypedEventHandler[object any, request comparable] interface {
	// Create is called in response to a create event - e.g. Pod Creation.
	Create(context.Context, event.TypedCreateEvent[object], workqueue.TypedRateLimitingInterface[request])

	// Update is called in response to an update event -  e.g. Pod Updated.
	Update(context.Context, event.TypedUpdateEvent[object], workqueue.TypedRateLimitingInterface[request])

	// Delete is called in response to a delete event - e.g. Pod Deleted.
	Delete(context.Context, event.TypedDeleteEvent[object], workqueue.TypedRateLimitingInterface[request])

	// Generic is called in response to an event of an unknown type or a synthetic event triggered as a cron or
	// external trigger request - e.g. reconcile Autoscaling, or a Webhook.
	Generic(context.Context, event.TypedGenericEvent[object], workqueue.TypedRateLimitingInterface[request])
}

var _ EventHandler = Funcs{}

// Funcs implements eventhandler.
type Funcs = TypedFuncs[client.Object, reconcile.Request]

// TypedFuncs implements eventhandler.
//
// TypedFuncs is experimental and subject to future change.
type TypedFuncs[object any, request comparable] struct {
	// Create is called in response to an add event.  Defaults to no-op.
	// RateLimitingInterface is used to enqueue reconcile.Requests.
	CreateFunc func(context.Context, event.TypedCreateEvent[object], workqueue.TypedRateLimitingInterface[request])

	// Update is called in response to an update event.  Defaults to no-op.
	// RateLimitingInterface is used to enqueue reconcile.Requests.
	UpdateFunc func(context.Context, event.TypedUpdateEvent[object], workqueue.TypedRateLimitingInterface[request])

	// Delete is called in response to a delete event.  Defaults to no-op.
	// RateLimitingInterface is used to enqueue reconcile.Requests.
	DeleteFunc func(context.Context, event.TypedDeleteEvent[object], workqueue.TypedRateLimitingInterface[request])

	// GenericFunc is called in response to a generic event.  Defaults to no-op.
	// RateLimitingInterface is used to enqueue reconcile.Requests.
	GenericFunc func(context.Context, event.TypedGenericEvent[object], workqueue.TypedRateLimitingInterface[request])
}

// Create implements EventHandler.
func (h TypedFuncs[object, request]) Create(ctx context.Context, e event.TypedCreateEvent[object], q workqueue.TypedRateLimitingInterface[request]) {
	if h.CreateFunc != nil {
		h.CreateFunc(ctx, e, q)
	}
}

// Delete implements EventHandler.
func (h TypedFuncs[object, request]) Delete(ctx context.Context, e event.TypedDeleteEvent[object], q workqueue.TypedRateLimitingInterface[request]) {
	if h.DeleteFunc != nil {
		h.DeleteFunc(ctx, e, q)
	}
}

// Update implements EventHandler.
func (h TypedFuncs[object, request]) Update(ctx context.Context, e event.TypedUpdateEvent[object], q workqueue.TypedRateLimitingInterface[request]) {
	if h.UpdateFunc != nil {
		h.UpdateFunc(ctx, e, q)
	}
}

// Generic implements EventHandler.
func (h TypedFuncs[object, request]) Generic(ctx context.Context, e event.TypedGenericEvent[object], q workqueue.TypedRateLimitingInterface[request]) {
	if h.GenericFunc != nil {
		h.GenericFunc(ctx, e, q)
	}
}

// LowPriority is the priority set by WithLowPriorityWhenUnchanged
const LowPriority = -100

// WithLowPriorityWhenUnchanged reduces the priority of events stemming from the initial listwatch or from a resync if
// and only if a priorityqueue.PriorityQueue is used. If not, it does nothing.
func WithLowPriorityWhenUnchanged[object client.Object, request comparable](u TypedEventHandler[object, request]) TypedEventHandler[object, request] {
	return TypedFuncs[object, request]{
		CreateFunc: func(ctx context.Context, tce event.TypedCreateEvent[object], trli workqueue.TypedRateLimitingInterface[request]) {
			// Due to how the handlers are factored, we have to wrap the workqueue to be able
			// to inject custom behavior.
			u.Create(ctx, tce, workqueueWithCustomAddFunc[request]{
				TypedRateLimitingInterface: trli,
				addFunc: func(item request, q workqueue.TypedRateLimitingInterface[request]) {
					priorityQueue, isPriorityQueue := q.(priorityqueue.PriorityQueue[request])
					if !isPriorityQueue {
						q.Add(item)
						return
					}
					var priority int
					if isObjectUnchanged(tce) {
						priority = LowPriority
					}
					priorityQueue.AddWithOpts(priorityqueue.AddOpts{Priority: priority}, item)
				},
			})
		},
		UpdateFunc: func(ctx context.Context, tue event.TypedUpdateEvent[object], trli workqueue.TypedRateLimitingInterface[request]) {
			u.Update(ctx, tue, workqueueWithCustomAddFunc[request]{
				TypedRateLimitingInterface: trli,
				addFunc: func(item request, q workqueue.TypedRateLimitingInterface[request]) {
					priorityQueue, isPriorityQueue := q.(priorityqueue.PriorityQueue[request])
					if !isPriorityQueue {
						q.Add(item)
						return
					}
					var priority int
					if tue.ObjectOld.GetResourceVersion() == tue.ObjectNew.GetResourceVersion() {
						priority = LowPriority
					}
					priorityQueue.AddWithOpts(priorityqueue.AddOpts{Priority: priority}, item)
				},
			})
		},
		DeleteFunc:  u.Delete,
		GenericFunc: u.Generic,
	}
}

type workqueueWithCustomAddFunc[request comparable] struct {
	workqueue.TypedRateLimitingInterface[request]
	addFunc func(item request, q workqueue.TypedRateLimitingInterface[request])
}

func (w workqueueWithCustomAddFunc[request]) Add(item request) {
	w.addFunc(item, w.TypedRateLimitingInterface)
}

// isObjectUnchanged checks if the object in a create event is unchanged, for example because
// we got it in our initial listwatch. The heuristic it uses is to check if the object is older
// than one minute.
func isObjectUnchanged[object client.Object](e event.TypedCreateEvent[object]) bool {
	return e.Object.GetCreationTimestamp().Time.Before(time.Now().Add(-time.Minute))
}
