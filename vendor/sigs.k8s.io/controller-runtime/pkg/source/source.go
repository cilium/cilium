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

package source

import (
	"context"
	"errors"
	"fmt"
	"sync"

	toolscache "k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	logf "sigs.k8s.io/controller-runtime/pkg/internal/log"
	internal "sigs.k8s.io/controller-runtime/pkg/internal/source"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
)

var logInformer = logf.RuntimeLog.WithName("source").WithName("Informer")

// Source is a source of events (e.g. Create, Update, Delete operations on Kubernetes Objects, Webhook callbacks, etc)
// which should be processed by event.EventHandlers to enqueue reconcile.Requests.
//
// * Use Kind for events originating in the cluster (e.g. Pod Create, Pod Update, Deployment Update).
//
// * Use Channel for events originating outside the cluster (e.g. GitHub Webhook callback, Polling external urls).
//
// Users may build their own Source implementations.
type Source = TypedSource[reconcile.Request]

// TypedSource is a generic source of events (e.g. Create, Update, Delete operations on Kubernetes Objects, Webhook callbacks, etc)
// which should be processed by event.EventHandlers to enqueue a request.
//
// * Use Kind for events originating in the cluster (e.g. Pod Create, Pod Update, Deployment Update).
//
// * Use Channel for events originating outside the cluster (e.g. GitHub Webhook callback, Polling external urls).
//
// Users may build their own Source implementations.
type TypedSource[request comparable] interface {
	// Start is internal and should be called only by the Controller to start the source.
	// Start must be non-blocking.
	Start(context.Context, workqueue.TypedRateLimitingInterface[request]) error
}

// SyncingSource is a source that needs syncing prior to being usable. The controller
// will call its WaitForSync prior to starting workers.
type SyncingSource = TypedSyncingSource[reconcile.Request]

// TypedSyncingSource is a source that needs syncing prior to being usable. The controller
// will call its WaitForSync prior to starting workers.
type TypedSyncingSource[request comparable] interface {
	TypedSource[request]
	WaitForSync(ctx context.Context) error
}

// Kind creates a KindSource with the given cache provider.
func Kind[object client.Object](
	cache cache.Cache,
	obj object,
	handler handler.TypedEventHandler[object, reconcile.Request],
	predicates ...predicate.TypedPredicate[object],
) SyncingSource {
	return TypedKind(cache, obj, handler, predicates...)
}

// TypedKind creates a KindSource with the given cache provider.
func TypedKind[object client.Object, request comparable](
	cache cache.Cache,
	obj object,
	handler handler.TypedEventHandler[object, request],
	predicates ...predicate.TypedPredicate[object],
) TypedSyncingSource[request] {
	return &internal.Kind[object, request]{
		Type:       obj,
		Cache:      cache,
		Handler:    handler,
		Predicates: predicates,
	}
}

var _ Source = &channel[string, reconcile.Request]{}

// ChannelOpt allows to configure a source.Channel.
type ChannelOpt[object any, request comparable] func(*channel[object, request])

// WithPredicates adds the configured predicates to a source.Channel.
func WithPredicates[object any, request comparable](p ...predicate.TypedPredicate[object]) ChannelOpt[object, request] {
	return func(c *channel[object, request]) {
		c.predicates = append(c.predicates, p...)
	}
}

// WithBufferSize configures the buffer size for a source.Channel. By
// default, the buffer size is 1024.
func WithBufferSize[object any, request comparable](bufferSize int) ChannelOpt[object, request] {
	return func(c *channel[object, request]) {
		c.bufferSize = &bufferSize
	}
}

// Channel is used to provide a source of events originating outside the cluster
// (e.g. GitHub Webhook callback).  Channel requires the user to wire the external
// source (e.g. http handler) to write GenericEvents to the underlying channel.
func Channel[object any](
	source <-chan event.TypedGenericEvent[object],
	handler handler.TypedEventHandler[object, reconcile.Request],
	opts ...ChannelOpt[object, reconcile.Request],
) Source {
	return TypedChannel[object, reconcile.Request](source, handler, opts...)
}

// TypedChannel is used to provide a source of events originating outside the cluster
// (e.g. GitHub Webhook callback).  Channel requires the user to wire the external
// source (e.g. http handler) to write GenericEvents to the underlying channel.
func TypedChannel[object any, request comparable](
	source <-chan event.TypedGenericEvent[object],
	handler handler.TypedEventHandler[object, request],
	opts ...ChannelOpt[object, request],
) TypedSource[request] {
	c := &channel[object, request]{
		source:  source,
		handler: handler,
	}
	for _, opt := range opts {
		opt(c)
	}

	return c
}

type channel[object any, request comparable] struct {
	// once ensures the event distribution goroutine will be performed only once
	once sync.Once

	// source is the source channel to fetch GenericEvents
	source <-chan event.TypedGenericEvent[object]

	handler handler.TypedEventHandler[object, request]

	predicates []predicate.TypedPredicate[object]

	bufferSize *int

	// dest is the destination channels of the added event handlers
	dest []chan event.TypedGenericEvent[object]

	// destLock is to ensure the destination channels are safely added/removed
	destLock sync.Mutex
}

func (cs *channel[object, request]) String() string {
	return fmt.Sprintf("channel source: %p", cs)
}

// Start implements Source and should only be called by the Controller.
func (cs *channel[object, request]) Start(
	ctx context.Context,
	queue workqueue.TypedRateLimitingInterface[request],
) error {
	// Source should have been specified by the user.
	if cs.source == nil {
		return fmt.Errorf("must specify Channel.Source")
	}
	if cs.handler == nil {
		return errors.New("must specify Channel.Handler")
	}

	if cs.bufferSize == nil {
		cs.bufferSize = ptr.To(1024)
	}

	dst := make(chan event.TypedGenericEvent[object], *cs.bufferSize)

	cs.destLock.Lock()
	cs.dest = append(cs.dest, dst)
	cs.destLock.Unlock()

	cs.once.Do(func() {
		// Distribute GenericEvents to all EventHandler / Queue pairs Watching this source
		go cs.syncLoop(ctx)
	})

	go func() {
		for evt := range dst {
			shouldHandle := true
			for _, p := range cs.predicates {
				if !p.Generic(evt) {
					shouldHandle = false
					break
				}
			}

			if shouldHandle {
				func() {
					ctx, cancel := context.WithCancel(ctx)
					defer cancel()
					cs.handler.Generic(ctx, evt, queue)
				}()
			}
		}
	}()

	return nil
}

func (cs *channel[object, request]) doStop() {
	cs.destLock.Lock()
	defer cs.destLock.Unlock()

	for _, dst := range cs.dest {
		close(dst)
	}
}

func (cs *channel[object, request]) distribute(evt event.TypedGenericEvent[object]) {
	cs.destLock.Lock()
	defer cs.destLock.Unlock()

	for _, dst := range cs.dest {
		// We cannot make it under goroutine here, or we'll meet the
		// race condition of writing message to closed channels.
		// To avoid blocking, the dest channels are expected to be of
		// proper buffer size. If we still see it blocked, then
		// the controller is thought to be in an abnormal state.
		dst <- evt
	}
}

func (cs *channel[object, request]) syncLoop(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			// Close destination channels
			cs.doStop()
			return
		case evt, stillOpen := <-cs.source:
			if !stillOpen {
				// if the source channel is closed, we're never gonna get
				// anything more on it, so stop & bail
				cs.doStop()
				return
			}
			cs.distribute(evt)
		}
	}
}

// Informer is used to provide a source of events originating inside the cluster from Watches (e.g. Pod Create).
type Informer struct {
	// Informer is the controller-runtime Informer
	Informer   cache.Informer
	Handler    handler.EventHandler
	Predicates []predicate.Predicate
}

var _ Source = &Informer{}

// Start is internal and should be called only by the Controller to register an EventHandler with the Informer
// to enqueue reconcile.Requests.
func (is *Informer) Start(ctx context.Context, queue workqueue.TypedRateLimitingInterface[reconcile.Request]) error {
	// Informer should have been specified by the user.
	if is.Informer == nil {
		return fmt.Errorf("must specify Informer.Informer")
	}
	if is.Handler == nil {
		return errors.New("must specify Informer.Handler")
	}

	_, err := is.Informer.AddEventHandlerWithOptions(internal.NewEventHandler(ctx, queue, is.Handler, is.Predicates), toolscache.HandlerOptions{
		Logger: &logInformer,
	})
	if err != nil {
		return err
	}
	return nil
}

func (is *Informer) String() string {
	return fmt.Sprintf("informer source: %p", is.Informer)
}

var _ Source = Func(nil)

// Func is a function that implements Source.
type Func = TypedFunc[reconcile.Request]

// TypedFunc is a function that implements Source.
type TypedFunc[request comparable] func(context.Context, workqueue.TypedRateLimitingInterface[request]) error

// Start implements Source.
func (f TypedFunc[request]) Start(ctx context.Context, queue workqueue.TypedRateLimitingInterface[request]) error {
	return f(ctx, queue)
}

func (f TypedFunc[request]) String() string {
	return fmt.Sprintf("func source: %p", f)
}
