// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package resource

import (
	"context"
	"fmt"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"sync"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	k8sRuntime "k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
	"sigs.k8s.io/controller-runtime/pkg/client/apiutil"

	"github.com/cilium/cilium/pkg/hive/cell"
	k8smetrics "github.com/cilium/cilium/pkg/k8s/metrics"
	"github.com/cilium/cilium/pkg/k8s/watchers/resources"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/promise"
	"github.com/cilium/cilium/pkg/stream"
)

// Resource provides access to a Kubernetes resource through either
// a stream of events or a read-only store.
//
// Observing of the events can be done from a constructor as subscriber
// registration is non-blocking.
//
// Store() however should only be called from a start hook, or from a
// goroutine forked from the start hook as it blocks until the store
// has been synchronized.
//
// The subscriber can process the events from Events() asynchronously and in
// parallel, but for each event the Done() function must be called to mark
// the event as handled. If not done no new events will be emitted for this key.
// If an event handling is marked as failed the configured error handler is called
// (WithErrorHandler). The default error handler will requeue the event (by its key) for
// later retried processing. The requeueing is rate limited and can be configured with
// WithRateLimiter option to Events().
//
// The resource is lazy, e.g. it will not start the informer until a call
// has been made to Events() or Store().
type Resource[T k8sRuntime.Object] interface {
	// Resource can be observed either via Observe() or via Events(). The observable
	// is implemented in terms of Events() and same semantics apply.
	stream.Observable[Event[T]]

	// Events returns a channel of events. Each event must be marked as handled
	// with a call to Done() which marks the key processed. No new events for this key
	// will be emitted before Done() is called.
	//
	// A missing Done() will lead to an eventual panic (via finalizer on Event[T]).
	// Panic on this situation is needed as otherwise no new events would be emitted
	// and thus this needs to be enforced.
	//
	// A stream of Upsert events are emitted first to replay the current state of the
	// store after which incremental upserts and deletes follow until the underlying
	// store is synchronized after which a Sync event is emitted and further incremental
	// updates:
	//
	//	(start observing), Upsert, Upsert, Upsert, (done replaying store contents), Upsert, Upsert,
	//	  (store synchronized with API server), Sync, Upsert, Delete, Upsert, ...
	//
	// The emitting of the Sync event does not depend on whether or not Upsert events have
	// all been marked Done() without an error. The sync event solely signals that the underlying
	// store has synchronized and that Upsert events for objects in a synchronized store have been
	// sent to the observer.
	//
	// When Done() is called with non-nil error the error handler is invoked, which
	// can ignore, requeue the event (by key) or close the channel. The default error handler
	// will requeue.
	//
	// If an Upsert is retried and the object has been deleted, a Delete event will be emitted instead.
	// Conversely if a Delete event is retried and the object has been recreated with the same key,
	// an Upsert will be emitted instead.
	//
	// If an objects is created and immediately deleted, then a slow observer may not observe this at
	// all. In all cases a Delete event is only emitted if the observer has seen an Upsert. Whether or
	// not it had been successfully handled (via Done(nil)) does not affect this property.
	Events(ctx context.Context, opts ...EventsOpt) <-chan Event[T]

	// Store retrieves the read-only store for the resource. Blocks until
	// the store has been synchronized or the context cancelled.
	// Returns a non-nil error if context is cancelled or the resource
	// has been stopped before store has synchronized.
	Store(context.Context) (Store[T], error)
}

// New creates a new Resource[T]. Use with hive.Provide:
//
//	var exampleCell = hive.Module(
//		"example",
//	 	cell.Provide(
//		 	// Provide `Resource[*slim_corev1.Pod]` to the hive:
//		 	func(lc cell.Lifecycle, c k8sClient.Clientset) resource.Resource[*slim_corev1.Pod] {
//				lw := utils.ListerWatcherFromTyped[*slim_corev1.PodList](
//					c.Slim().CoreV1().Pods(""),
//				)
//		 		return resource.New(lc, lw)
//		 	}
//		}),
//		...
//	)
//
//	func usePods(pods resource.Resource[*slim_corev1.Pod]) {
//		go func() {
//			for ev := range podEvents {
//		   		onPodEvent(ev)
//		   	}
//		}
//		return e
//	}
//	func onPodEvent(event resource.Event[*slim_core.Pod]) {
//		switch event.Kind {
//		case resource.Sync:
//			// Pods have now been synced and the set of Upsert events
//			// received thus far forms a coherent snapshot.
//
//			// Must always call event.Done(error) to mark the event as processed.
//			event.Done(nil)
//		case resource.Upsert:
//			event.Done(onPodUpsert(event.Object))
//		case resource.Delete:
//			event.Done(onPodDelete(event.Object))
//		}
//	}
//
// See also pkg/k8s/resource/example/main.go for a runnable example.
func New[T k8sRuntime.Object](lc cell.Lifecycle, lw cache.ListerWatcher, opts ...ResourceOption) Resource[T] {
	r := &resource[T]{
		lw: lw,
	}
	r.opts.sourceObj = func() k8sRuntime.Object {
		var obj T
		return obj
	}
	for _, o := range opts {
		o(&r.opts)
	}
	r.ctx, r.cancel = context.WithCancel(context.Background())
	r.reset()
	lc.Append(r)
	return r
}

type options struct {
	transform   cache.TransformFunc      // if non-nil, the object is transformed with this function before storing
	sourceObj   func() k8sRuntime.Object // prototype for the object before it is transformed
	indexers    cache.Indexers           // map of the optional custom indexers to be added to the underlying resource informer
	metricScope string                   // the scope label used when recording metrics for the resource
	name        string                   // the name label used for the workqueue metrics
	releasable  bool                     // if true, the underlying informer will be stopped when the last subscriber cancels its subscription
}

type ResourceOption func(o *options)

// WithTransform sets the function to transform the object before storing it.
func WithTransform[From, To k8sRuntime.Object](transform func(From) (To, error)) ResourceOption {
	return WithLazyTransform(
		func() k8sRuntime.Object {
			var obj From
			return obj
		},
		func(fromRaw any) (any, error) {
			if from, ok := fromRaw.(From); ok {
				to, err := transform(from)
				return to, err
			} else {
				var obj From
				return nil, fmt.Errorf("resource.WithTransform: expected %T, got %T", obj, fromRaw)
			}
		})
}

// WithLazyTransform sets the function to transform the object before storing it.
// Unlike "WithTransform", this defers the resolving of the source object type until the resource
// is needed. Use this in situations where the source object depends on api-server capabilities.
func WithLazyTransform(sourceObj func() k8sRuntime.Object, transform cache.TransformFunc) ResourceOption {
	return func(o *options) {
		o.sourceObj = sourceObj
		o.transform = transform
	}
}

// WithMetric enables metrics collection for the resource using the provided scope.
func WithMetric(scope string) ResourceOption {
	return func(o *options) {
		o.metricScope = scope
	}
}

// WithIndexers sets additional custom indexers on the resource store.
func WithIndexers(indexers cache.Indexers) ResourceOption {
	return func(o *options) {
		o.indexers = indexers
	}
}

// WithName sets the name of the resource. Used for workqueue metrics.
func WithName(name string) ResourceOption {
	return func(o *options) {
		o.name = name
	}
}

// WithStoppableInformer marks the resource as releasable. A releasable resource stops
// the underlying informer if the last active subscriber cancels its subscription.
// In this case the resource is stopped and prepared again for a subsequent call to
// either Events() or Store().
// A subscriber is a consumer who has taken a reference to the store with Store() or that
// is listening to the events stream channel with Events().
// This option is meant to be used for very specific cases of resources with a high rate
// of updates that can potentially hinder scalability in very large clusters, like
// CiliumNode and CiliumEndpoint.
// For this cases, stopping the informer is required when switching to other data sources
// that scale better.
func WithStoppableInformer() ResourceOption {
	return func(o *options) {
		o.releasable = true
	}
}

type resource[T k8sRuntime.Object] struct {
	mu     lock.RWMutex
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
	opts   options

	needed chan struct{}

	subscribers map[uint64]*subscriber[T]
	subId       uint64

	lw           cache.ListerWatcher
	synchronized bool // flipped to true when informer has synced.

	storePromise  promise.Promise[Store[T]]
	storeResolver promise.Resolver[Store[T]]

	// meaningful for releasable resources only
	refsMu      lock.Mutex
	refs        uint64
	resetCtx    context.Context
	resetCancel context.CancelFunc
}

var _ Resource[*corev1.Node] = &resource[*corev1.Node]{}

func (r *resource[T]) Store(ctx context.Context) (Store[T], error) {
	r.markNeeded()

	// Wait until store has synchronized to avoid querying a store
	// that has not finished the initial listing.
	hasSynced := func() bool {
		r.mu.RLock()
		defer r.mu.RUnlock()
		return r.synchronized
	}
	cache.WaitForCacheSync(ctx.Done(), hasSynced)

	// use an error handler to release the resource if the store promise
	// is rejected or the context is cancelled before the cache has synchronized.
	return promise.MapError(r.storePromise, func(err error) error {
		r.release()
		return err
	}).Await(ctx)
}

func (r *resource[T]) metricEventProcessed(eventKind EventKind, status bool) {
	if r.opts.metricScope == "" {
		return
	}

	result := "success"
	if !status {
		result = "failed"
	}

	var action string
	switch eventKind {
	case Sync:
		return
	case Upsert:
		action = "update"
	case Delete:
		action = "delete"
	}

	metrics.KubernetesEventProcessed.WithLabelValues(r.opts.metricScope, action, result).Inc()
}

func (r *resource[T]) metricEventReceived(action string, valid, equal bool) {
	if r.opts.metricScope == "" {
		return
	}

	k8smetrics.LastInteraction.Reset()

	metrics.EventTS.WithLabelValues(metrics.LabelEventSourceK8s, r.opts.metricScope, action).SetToCurrentTime()
	validStr := strconv.FormatBool(valid)
	equalStr := strconv.FormatBool(equal)
	metrics.KubernetesEventReceived.WithLabelValues(r.opts.metricScope, action, validStr, equalStr).Inc()
}

func (r *resource[T]) Start(cell.HookContext) error {
	r.start()
	return nil
}

func (r *resource[T]) start() {
	// Don't start the resource if it has been definitely stopped
	if r.ctx.Err() != nil {
		return
	}
	r.wg.Add(1)
	go r.startWhenNeeded()
}

func (r *resource[T]) markNeeded() {
	if r.opts.releasable {
		r.refsMu.Lock()
		r.refs++
		r.refsMu.Unlock()
	}

	select {
	case r.needed <- struct{}{}:
	default:
	}
}

func (r *resource[T]) startWhenNeeded() {
	defer r.wg.Done()

	// Wait until we're needed before starting the informer.
	select {
	case <-r.ctx.Done():
		return
	case <-r.needed:
	}

	// Short-circuit if we're being stopped.
	if r.ctx.Err() != nil {
		return
	}

	store, informer := r.newInformer()
	r.storeResolver.Resolve(&typedStore[T]{
		store:   store,
		release: r.release,
	})

	r.wg.Add(1)
	go func() {
		defer r.wg.Done()
		informer.Run(merge(r.ctx.Done(), r.resetCtx.Done()))
	}()

	// Wait for cache to be synced before emitting the sync event.
	if cache.WaitForCacheSync(merge(r.ctx.Done(), r.resetCtx.Done()), informer.HasSynced) {
		// Emit the sync event for all subscribers. Subscribers
		// that subscribe afterwards will emit it by checking
		// r.synchronized.
		r.mu.Lock()
		for _, sub := range r.subscribers {
			sub.enqueueSync()
		}
		r.synchronized = true
		r.mu.Unlock()
	}
}

func (r *resource[T]) Stop(stopCtx cell.HookContext) error {
	if r.opts.releasable {
		// grab the refs lock to avoid a concurrent restart for releasable resource
		r.refsMu.Lock()
		defer r.refsMu.Unlock()
	}

	r.cancel()
	r.wg.Wait()
	return nil
}

type eventsOpts struct {
	rateLimiter  workqueue.RateLimiter
	errorHandler ErrorHandler
}

type EventsOpt func(*eventsOpts)

// WithRateLimiter sets the rate limiting algorithm to be used when requeueing failed events.
func WithRateLimiter(r workqueue.RateLimiter) EventsOpt {
	return func(o *eventsOpts) {
		o.rateLimiter = r
	}
}

// WithErrorHandler specifies the error handling strategy for failed events. By default
// the strategy is to always requeue the processing of a failed event.
func WithErrorHandler(h ErrorHandler) EventsOpt {
	return func(o *eventsOpts) {
		o.errorHandler = h
	}
}

func (r *resource[T]) Observe(ctx context.Context, next func(Event[T]), complete func(error)) {
	stream.FromChannel(r.Events(ctx)).Observe(ctx, next, complete)
}

// Events subscribes the caller to resource events.
//
// Each subscriber has their own queues and can process events at their own
// rate. Only object keys are queued and if an object is changed multiple times
// before the subscriber can handle the event only the latest state of object
// is emitted.
//
// The 'ctx' is used to cancel the subscription. The returned channel will be
// closed when context is cancelled.
//
// Options are supported to configure rate limiting of retries
// (WithRateLimiter), error handling strategy (WithErrorHandler).
//
// By default all errors are retried, the default rate limiter of workqueue
// package is used and the channel is unbuffered.
func (r *resource[T]) Events(ctx context.Context, opts ...EventsOpt) <-chan Event[T] {
	_, callerFile, callerLine, _ := runtime.Caller(1)
	debugInfo := fmt.Sprintf("%T.Events() called from %s:%d", r, callerFile, callerLine)

	options := eventsOpts{
		errorHandler: AlwaysRetry, // Default error handling is to always retry.
		rateLimiter:  workqueue.DefaultControllerRateLimiter(),
	}
	for _, apply := range opts {
		apply(&options)
	}

	// Mark the resource as needed. This will start the informer if it was not already.
	r.markNeeded()

	out := make(chan Event[T])
	ctx, subCancel := context.WithCancel(ctx)

	sub := &subscriber[T]{
		r:         r,
		options:   options,
		debugInfo: debugInfo,
		wq: workqueue.NewRateLimitingQueueWithConfig(options.rateLimiter,
			workqueue.RateLimitingQueueConfig{Name: r.resourceName()}),
	}

	// Fork a goroutine to process the queued keys and pass them to the subscriber.
	r.wg.Add(1)
	go func() {
		defer r.release()
		defer r.wg.Done()
		defer close(out)

		// Grab a handle to the store. Asynchronous as informer is started in the background.
		store, err := r.storePromise.Await(ctx)
		if err != nil {
			// Subscriber cancelled before the informer started, bail out.
			return
		}

		r.mu.Lock()
		subId := r.subId
		r.subId++
		r.subscribers[subId] = sub

		// Populate the queue with the initial set of keys that are already
		// in the store. Done under the resource lock to synchronize with delta
		// processing to make sure we don't end up queuing the key as initial key,
		// processing it and then requeuing it again.
		initialKeys := store.IterKeys()
		for initialKeys.Next() {
			sub.enqueueKey(initialKeys.Key())
		}

		// If the informer is already synchronized, then the above set of keys is a consistent
		// snapshot and we can queue the sync entry. If we're not yet synchronized the sync will
		// be queued from startWhenNeeded() after the informer has synchronized.
		if r.synchronized {
			sub.enqueueSync()
		}
		r.mu.Unlock()

		sub.processLoop(ctx, out, store)

		r.mu.Lock()
		delete(r.subscribers, subId)
		r.mu.Unlock()
	}()

	// Fork a goroutine to wait for either the subscriber cancelling or the resource
	// shutting down.
	r.wg.Add(1)
	go func() {
		defer r.wg.Done()
		select {
		case <-r.ctx.Done():
		case <-r.resetCtx.Done():
		case <-ctx.Done():
		}
		subCancel()
		sub.wq.ShutDownWithDrain()
	}()

	return out
}

func (r *resource[T]) release() {
	if !r.opts.releasable {
		return
	}

	// in case of a releasable resource, stop the underlying informer when the last
	// reference to it is released. The resource is restarted to be
	// ready again in case of a subsequent call to either Events() or Store().

	r.refsMu.Lock()
	defer r.refsMu.Unlock()

	r.refs--
	if r.refs > 0 {
		return
	}

	r.resetCancel()
	r.wg.Wait()
	close(r.needed)

	r.reset()
	r.start()
}

func (r *resource[T]) reset() {
	r.subscribers = make(map[uint64]*subscriber[T])
	r.needed = make(chan struct{}, 1)
	r.synchronized = false
	r.storeResolver, r.storePromise = promise.New[Store[T]]()
	r.resetCtx, r.resetCancel = context.WithCancel(context.Background())
}

func (r *resource[T]) resourceName() string {
	if r.opts.name != "" {
		return r.opts.name
	}

	// We create a new pointer to the reconciled resource type.
	// For example, with resource[*cilium_api_v2.CiliumNode] new(T) returns **cilium_api_v2.CiliumNode
	// and *new(T) is nil. So we create a new pointer using reflect.New()
	o := *new(T)
	sourceObj := reflect.New(reflect.TypeOf(o).Elem()).Interface().(T)

	gvk, err := apiutil.GVKForObject(sourceObj, scheme)
	if err != nil {
		return ""
	}

	return strings.ToLower(gvk.Kind)
}

type subscriber[T k8sRuntime.Object] struct {
	r         *resource[T]
	debugInfo string
	wq        workqueue.RateLimitingInterface
	options   eventsOpts
}

func (s *subscriber[T]) processLoop(ctx context.Context, out chan Event[T], store Store[T]) {
	// Make sure to call ShutDown() in the end. Calling ShutDownWithDrain is not
	// enough as DelayingQueue does not implement it, so without ShutDown() we'd
	// leak the (*delayingType).waitingLoop.
	defer s.wq.ShutDown()

	doneFinalizer := func(done *bool) {
		// If you get here it is because an Event[T] was handed to a subscriber
		// that forgot to call Event[T].Done().
		//
		// Calling Done() is needed to mark the event as handled. This allows
		// the next event for the same key to be handled and is used to clear
		// rate limiting and retry counts of prior failures.
		panic(fmt.Sprintf(
			"%s has a broken event handler that did not call Done() "+
				"before event was garbage collected",
			s.debugInfo))
	}

	// To synthesize delete events to the subscriber we keep track of the last know state
	// of the object given to the subscriber. Objects are cleaned from this map when delete
	// events are successfully processed.
	var lastKnownObjects lastKnownObjects[T]

loop:
	for {
		// Retrieve an item from the subscribers queue and then fetch the object
		// from the store.
		workItem, shutdown := s.getWorkItem()
		if shutdown {
			break
		}

		var event Event[T]

		switch workItem := workItem.(type) {
		case syncWorkItem:
			event.Kind = Sync
		case keyWorkItem:
			obj, exists, err := store.GetByKey(workItem.key)
			if !exists || err != nil {
				// The object no longer exists in the store and thus has been deleted.
				deletedObject, ok := lastKnownObjects.Load(workItem.key)
				if !ok {
					// Object was never seen by the subscriber. Ignore the event.
					s.wq.Done(workItem)
					continue loop
				}
				event.Kind = Delete
				event.Key = workItem.key
				event.Object = deletedObject
			} else {
				lastKnownObjects.Store(workItem.key, obj)
				event.Kind = Upsert
				event.Key = workItem.key
				event.Object = obj
			}
		default:
			panic(fmt.Sprintf("%T: unknown work item %T", s.r, workItem))
		}

		// eventDoneSentinel is a heap allocated object referenced by Done().
		// If Done() is not called, a finalizer set on this object will be invoked
		// which panics. If Done() is called, the finalizer is unset.
		var eventDoneSentinel = new(bool)
		event.Done = func(err error) {
			runtime.SetFinalizer(eventDoneSentinel, nil)

			if err == nil && event.Kind == Delete {
				// Deletion processed successfully. Remove it from the set of
				// deleted objects unless it was replaced by an upsert or newer
				// deletion.
				lastKnownObjects.DeleteByUID(event.Key, event.Object)
			}

			s.eventDone(workItem, err)

			s.r.metricEventProcessed(event.Kind, err == nil)
		}

		// Add a finalizer to catch forgotten calls to Done().
		runtime.SetFinalizer(eventDoneSentinel, doneFinalizer)

		select {
		case out <- event:
		case <-ctx.Done():
			// Subscriber cancelled or resource is shutting down. We're not requiring
			// the subscriber to drain the channel, so we're marking the event done here
			// and not sending it.
			event.Done(nil)

			// Drain the queue without further processing.
			for {
				_, shutdown := s.getWorkItem()
				if shutdown {
					return
				}
			}
		}
	}
}

func (s *subscriber[T]) getWorkItem() (e workItem, shutdown bool) {
	var raw any
	raw, shutdown = s.wq.Get()
	if shutdown {
		return
	}
	return raw.(workItem), false
}

func (s *subscriber[T]) enqueueSync() {
	s.wq.Add(syncWorkItem{})
}

func (s *subscriber[T]) enqueueKey(key Key) {
	s.wq.Add(keyWorkItem{key})
}

func (s *subscriber[T]) eventDone(entry workItem, err error) {
	// This is based on the example found in k8s.io/client-go/examples/worsueue/main.go.

	// Mark the object as done being processed. If it was marked dirty
	// during processing, it'll be processed again.
	defer s.wq.Done(entry)

	if err != nil {
		numRequeues := s.wq.NumRequeues(entry)

		var action ErrorAction
		switch entry := entry.(type) {
		case syncWorkItem:
			action = s.options.errorHandler(Key{}, numRequeues, err)
		case keyWorkItem:
			action = s.options.errorHandler(entry.key, numRequeues, err)
		default:
			panic(fmt.Sprintf("keyQueue: unhandled entry %T", entry))
		}

		switch action {
		case ErrorActionRetry:
			s.wq.AddRateLimited(entry)
		case ErrorActionStop:
			s.wq.ShutDown()
		case ErrorActionIgnore:
			s.wq.Forget(entry)
		default:
			panic(fmt.Sprintf("keyQueue: unknown action %q from error handler %v", action, s.options.errorHandler))
		}
	} else {
		// As the object was processed successfully we can "forget" it.
		// This clears any rate limiter state associated with this object, so
		// it won't be throttled based on previous failure history.
		s.wq.Forget(entry)
	}
}

// lastKnownObjects stores the last known state of an object from a subscriber's
// perspective. It is used to emit delete events with the last known state of
// the object.
type lastKnownObjects[T k8sRuntime.Object] struct {
	mu   lock.RWMutex
	objs map[Key]T
}

func (l *lastKnownObjects[T]) Load(key Key) (obj T, ok bool) {
	l.mu.RLock()
	defer l.mu.RUnlock()
	obj, ok = l.objs[key]
	return
}

func (l *lastKnownObjects[T]) Store(key Key, obj T) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.objs == nil {
		l.objs = map[Key]T{}
	}
	l.objs[key] = obj
}

// DeleteByUID removes the object, but only if the UID matches. UID
// might not match if the object has been re-created with the same key
// after deletion and thus Store'd again here. Once that incarnation
// is deleted, we will be here again and the UID will match.
func (l *lastKnownObjects[T]) DeleteByUID(key Key, objToDelete T) {
	l.mu.Lock()
	defer l.mu.Unlock()

	if obj, ok := l.objs[key]; ok {
		if getUID(obj) == getUID(objToDelete) {
			delete(l.objs, key)
		}
	}
}

// workItem restricts the set of types we use when type-switching over the
// queue entries, so that we'll get a compiler error on impossible types.
//
// The queue entries must be kept comparable and not be pointers as we want
// to be able to coalesce multiple keyEntry's into a single element in the
// queue.
type workItem interface {
	isWorkItem()
}

// syncWorkItem marks the store as synchronized and thus a 'Sync' event can be
// emitted to the subscriber.
type syncWorkItem struct{}

func (syncWorkItem) isWorkItem() {}

// keyWorkItem marks work for a specific key. Whether this is an upsert or delete
// depends on the state of the store at the time this work item is processed.
type keyWorkItem struct {
	key Key
}

func (keyWorkItem) isWorkItem() {}

type wrapperController struct {
	cache.Controller
	cacheMutationDetector cache.MutationDetector
}

func (p *wrapperController) Run(stopCh <-chan struct{}) {
	go p.cacheMutationDetector.Run(stopCh)
	p.Controller.Run(stopCh)
}

func (r *resource[T]) newInformer() (cache.Indexer, cache.Controller) {
	clientState := cache.NewIndexer(cache.DeletionHandlingMetaNamespaceKeyFunc, r.opts.indexers)
	opts := cache.DeltaFIFOOptions{KeyFunction: cache.MetaNamespaceKeyFunc, KnownObjects: clientState}
	fifo := cache.NewDeltaFIFOWithOptions(opts)
	transformer := r.opts.transform
	cacheMutationDetector := cache.NewCacheMutationDetector(fmt.Sprintf("%T", r))
	cfg := &cache.Config{
		Queue:            fifo,
		ListerWatcher:    r.lw,
		ObjectType:       r.opts.sourceObj(),
		FullResyncPeriod: 0,
		RetryOnError:     false,
		Process: func(obj interface{}, isInInitialList bool) error {
			// Processing of the deltas is done under the resource mutex. This
			// avoids emitting double events for new subscribers that list the
			// keys in the store.
			r.mu.RLock()
			defer r.mu.RUnlock()

			for _, d := range obj.(cache.Deltas) {
				var obj interface{}
				if transformer != nil {
					var err error
					if obj, err = transformer(d.Object); err != nil {
						return err
					}
				} else {
					obj = d.Object
				}

				// In CI we detect if the objects were modified and panic
				// (e.g. when KUBE_CACHE_MUTATION_DETECTOR is set)
				// this is a no-op in production environments.
				cacheMutationDetector.AddObject(obj)

				key := NewKey(obj)

				switch d.Type {
				case cache.Sync, cache.Added, cache.Updated:
					metric := resources.MetricCreate
					if d.Type != cache.Added {
						metric = resources.MetricUpdate
					}
					r.metricEventReceived(metric, true, false)

					if _, exists, err := clientState.Get(obj); err == nil && exists {
						if err := clientState.Update(obj); err != nil {
							return err
						}
					} else {
						if err := clientState.Add(obj); err != nil {
							return err
						}
					}

					for _, sub := range r.subscribers {
						sub.enqueueKey(key)
					}
				case cache.Deleted:
					r.metricEventReceived(resources.MetricDelete, true, false)

					if err := clientState.Delete(obj); err != nil {
						return err
					}

					for _, sub := range r.subscribers {
						sub.enqueueKey(key)
					}
				}
			}
			return nil
		},
	}
	return clientState, &wrapperController{
		Controller:            cache.New(cfg),
		cacheMutationDetector: cacheMutationDetector,
	}
}

func getUID(obj k8sRuntime.Object) types.UID {
	meta, err := meta.Accessor(obj)
	if err != nil {
		// If we get here, it means the object does not implement ObjectMeta, and thus
		// the Resource[T] has been instantianted with an unsuitable type T.
		// As this would be catched immediately during development, panicing is the
		// way.
		panic(fmt.Sprintf("BUG: meta.Accessor() failed on %T: %s", obj, err))
	}
	return meta.GetUID()
}

func merge[T any](c1, c2 <-chan T) <-chan T {
	m := make(chan T)
	go func() {
		select {
		case <-c1:
		case <-c2:
		}
		close(m)
	}()
	return m
}
