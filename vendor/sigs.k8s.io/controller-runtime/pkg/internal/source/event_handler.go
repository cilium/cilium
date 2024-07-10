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

package internal

import (
	"context"
	"fmt"

	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	logf "sigs.k8s.io/controller-runtime/pkg/internal/log"

	"sigs.k8s.io/controller-runtime/pkg/predicate"
)

var log = logf.RuntimeLog.WithName("source").WithName("EventHandler")

// NewEventHandler creates a new EventHandler.
func NewEventHandler[T client.Object](ctx context.Context, queue workqueue.RateLimitingInterface, handler handler.TypedEventHandler[T], predicates []predicate.TypedPredicate[T]) *EventHandler[T] {
	return &EventHandler[T]{
		ctx:        ctx,
		handler:    handler,
		queue:      queue,
		predicates: predicates,
	}
}

// EventHandler adapts a handler.EventHandler interface to a cache.ResourceEventHandler interface.
type EventHandler[T client.Object] struct {
	// ctx stores the context that created the event handler
	// that is used to propagate cancellation signals to each handler function.
	ctx context.Context

	handler    handler.TypedEventHandler[T]
	queue      workqueue.RateLimitingInterface
	predicates []predicate.TypedPredicate[T]
}

// HandlerFuncs converts EventHandler to a ResourceEventHandlerFuncs
// TODO: switch to ResourceEventHandlerDetailedFuncs with client-go 1.27
func (e *EventHandler[T]) HandlerFuncs() cache.ResourceEventHandlerFuncs {
	return cache.ResourceEventHandlerFuncs{
		AddFunc:    e.OnAdd,
		UpdateFunc: e.OnUpdate,
		DeleteFunc: e.OnDelete,
	}
}

// OnAdd creates CreateEvent and calls Create on EventHandler.
func (e *EventHandler[T]) OnAdd(obj interface{}) {
	c := event.TypedCreateEvent[T]{}

	// Pull Object out of the object
	if o, ok := obj.(T); ok {
		c.Object = o
	} else {
		log.Error(nil, "OnAdd missing Object",
			"object", obj, "type", fmt.Sprintf("%T", obj))
		return
	}

	for _, p := range e.predicates {
		if !p.Create(c) {
			return
		}
	}

	// Invoke create handler
	ctx, cancel := context.WithCancel(e.ctx)
	defer cancel()
	e.handler.Create(ctx, c, e.queue)
}

// OnUpdate creates UpdateEvent and calls Update on EventHandler.
func (e *EventHandler[T]) OnUpdate(oldObj, newObj interface{}) {
	u := event.TypedUpdateEvent[T]{}

	if o, ok := oldObj.(T); ok {
		u.ObjectOld = o
	} else {
		log.Error(nil, "OnUpdate missing ObjectOld",
			"object", oldObj, "type", fmt.Sprintf("%T", oldObj))
		return
	}

	// Pull Object out of the object
	if o, ok := newObj.(T); ok {
		u.ObjectNew = o
	} else {
		log.Error(nil, "OnUpdate missing ObjectNew",
			"object", newObj, "type", fmt.Sprintf("%T", newObj))
		return
	}

	for _, p := range e.predicates {
		if !p.Update(u) {
			return
		}
	}

	// Invoke update handler
	ctx, cancel := context.WithCancel(e.ctx)
	defer cancel()
	e.handler.Update(ctx, u, e.queue)
}

// OnDelete creates DeleteEvent and calls Delete on EventHandler.
func (e *EventHandler[T]) OnDelete(obj interface{}) {
	d := event.TypedDeleteEvent[T]{}

	// Deal with tombstone events by pulling the object out.  Tombstone events wrap the object in a
	// DeleteFinalStateUnknown struct, so the object needs to be pulled out.
	// Copied from sample-controller
	// This should never happen if we aren't missing events, which we have concluded that we are not
	// and made decisions off of this belief.  Maybe this shouldn't be here?
	var ok bool
	if _, ok = obj.(client.Object); !ok {
		// If the object doesn't have Metadata, assume it is a tombstone object of type DeletedFinalStateUnknown
		tombstone, ok := obj.(cache.DeletedFinalStateUnknown)
		if !ok {
			log.Error(nil, "Error decoding objects.  Expected cache.DeletedFinalStateUnknown",
				"type", fmt.Sprintf("%T", obj),
				"object", obj)
			return
		}

		// Set DeleteStateUnknown to true
		d.DeleteStateUnknown = true

		// Set obj to the tombstone obj
		obj = tombstone.Obj
	}

	// Pull Object out of the object
	if o, ok := obj.(T); ok {
		d.Object = o
	} else {
		log.Error(nil, "OnDelete missing Object",
			"object", obj, "type", fmt.Sprintf("%T", obj))
		return
	}

	for _, p := range e.predicates {
		if !p.Delete(d) {
			return
		}
	}

	// Invoke delete handler
	ctx, cancel := context.WithCancel(e.ctx)
	defer cancel()
	e.handler.Delete(ctx, d, e.queue)
}
