// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package resource

import (
	"context"
	"fmt"
	"runtime"
	"sync"

	corev1 "k8s.io/api/core/v1"
	k8sRuntime "k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"

	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/promise"
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
	// Events returns a channel of events. Each event must be marked as handled
	// with a call to Done(), otherwise no new events for this key will be emitted.
	//
	// When Done() is called with non-nil error the error handler is invoked, which
	// can ignore, requeue the event or close the channel. The default error handler
	// will requeue.
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
//		 	func(lc hive.Lifecycle, c k8sClient.Clientset) resource.Resource[*slim_corev1.Pod] {
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
func New[T k8sRuntime.Object](lc hive.Lifecycle, lw cache.ListerWatcher) Resource[T] {
	r := &resource[T]{
		queues: make(map[uint64]*keyQueue),
		needed: make(chan struct{}, 1),
		lw:     lw,
	}
	r.ctx, r.cancel = context.WithCancel(context.Background())
	r.storeResolver, r.storePromise = promise.New[Store[T]]()
	lc.Append(r)
	return r
}

type resource[T k8sRuntime.Object] struct {
	mu     lock.RWMutex
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	needed chan struct{}

	queues map[uint64]*keyQueue
	subId  uint64

	lw           cache.ListerWatcher
	synchronized bool // flipped to true when informer has synced.

	storePromise  promise.Promise[Store[T]]
	storeResolver promise.Resolver[Store[T]]
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
	if !cache.WaitForCacheSync(ctx.Done(), hasSynced) {
		return nil, ctx.Err()
	}

	return r.storePromise.Await(ctx)
}

func (r *resource[T]) pushUpdate(key Key) {
	r.mu.RLock()
	for _, queue := range r.queues {
		queue.AddUpsert(key)
	}
	r.mu.RUnlock()
}

func (r *resource[T]) pushDelete(lastState any) {
	key := NewKey(lastState)
	obj := lastState
	if d, ok := lastState.(cache.DeletedFinalStateUnknown); ok {
		obj = d.Obj
	}
	r.mu.RLock()
	for _, queue := range r.queues {
		queue.AddDelete(key, obj)
	}
	r.mu.RUnlock()
}

func (r *resource[T]) Start(hive.HookContext) error {
	r.wg.Add(1)
	go r.startWhenNeeded()
	return nil
}

func (r *resource[T]) markNeeded() {
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

	// Construct the informer and run it.
	var objType T
	handlerFuncs :=
		cache.ResourceEventHandlerFuncs{
			AddFunc:    func(obj any) { r.pushUpdate(NewKey(obj)) },
			UpdateFunc: func(old any, new any) { r.pushUpdate(NewKey(new)) },
			DeleteFunc: func(obj any) { r.pushDelete(obj) },
		}

	store, informer := cache.NewInformer(r.lw, objType, 0, handlerFuncs)
	r.storeResolver.Resolve(&typedStore[T]{store})

	r.wg.Add(1)
	go func() {
		defer r.wg.Done()
		informer.Run(r.ctx.Done())
	}()

	// Wait for cache to be synced before emitting the sync events.
	if cache.WaitForCacheSync(r.ctx.Done(), informer.HasSynced) {
		// Emit the sync event for all subscribers. Subscribers
		// that subscribe afterwards will emit it by checking
		// r.synchronized.
		r.mu.Lock()
		for _, queue := range r.queues {
			queue.AddSync()
		}
		r.synchronized = true
		r.mu.Unlock()
	}
}

func (r *resource[T]) Stop(stopCtx hive.HookContext) error {
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

// Events subscribes the caller to resource events.
//
// Each subscriber has their own queues and can process events at their own
// rate. Only object keys are queued and if an object is changed multiple times
// before the subscriber can handle the event only the latest state of object
// is emitted.
//
// The 'ctx' is used to cancel the subscription. If cancelled, the subscriber
// must drain the event channel.
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

	ctx, subCancel := context.WithCancel(ctx)

	// Create a queue for receiving the events from the informer.
	queue := &keyQueue{
		RateLimitingInterface: workqueue.NewRateLimitingQueue(options.rateLimiter),
		errorHandler:          options.errorHandler,
	}
	r.mu.Lock()
	subId := r.subId
	r.subId++
	r.mu.Unlock()

	out := make(chan Event[T])

	// Fork a goroutine to pop elements from the queue and pass them to the subscriber.
	r.wg.Add(1)
	go func() {
		defer r.wg.Done()

		// Make sure to call ShutDown() in the end. Calling ShutDownWithDrain is not
		// enough as DelayingQueue does not implement it, so without ShutDown() we'd
		// leak the (*delayingType).waitingLoop.
		defer queue.ShutDown()

		defer close(out)

		// Grab a handle to the store. Asynchronous as informer is started in the background.
		store, err := r.storePromise.Await(ctx)
		if err != nil {
			// Subscriber cancelled before the informer started, bail out.
			return
		}

		r.mu.Lock()
		r.queues[subId] = queue

		// Append the current set of keys to the queue.
		keyIter := store.IterKeys()
		for keyIter.Next() {
			queue.AddUpsert(keyIter.Key())
		}

		// If the informer is already synchronized, then the above set of keys is a consistent
		// snapshot and we can queue the sync entry. If we're not yet synchronized the sync will
		// be queued from startWhenNeeded() after the informer has synchronized.
		if r.synchronized {
			queue.AddSync()
		}
		r.mu.Unlock()

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
				debugInfo))
		}

	loop:
		for {
			// Retrieve an item from the subscribers queue and then fetch the object
			// from the store.
			raw, shutdown := queue.Get()
			if shutdown {
				break
			}
			entry := raw.(queueEntry)

			var (
				// eventDoneSentinel is a heap allocated object referenced by Done().
				// If Done() is not called, a finalizer set on this object will be invoked
				// which panics. If Done() is called, the finalizer is unset.
				eventDoneSentinel = new(bool)
				event             Event[T]
			)
			event.Done = func(err error) {
				runtime.SetFinalizer(eventDoneSentinel, nil)
				queue.eventDone(entry, err)
			}

			// Add a finalizer to catch forgotten calls to Done().
			runtime.SetFinalizer(eventDoneSentinel, doneFinalizer)

			switch entry := entry.(type) {
			case syncEntry:
				event.Kind = Sync
			case deleteEntry:
				event.Kind = Delete
				event.Key = entry.key
				event.Object = entry.obj.(T)
			case upsertEntry:
				obj, exists, err := store.GetByKey(entry.key)
				// If the item didn't exist, then it's been deleted and a delete event will
				// follow soon.
				if err != nil || !exists {
					event.Done(nil)
					continue loop
				}
				event.Kind = Upsert
				event.Key = entry.key
				event.Object = obj
			default:
				panic(fmt.Sprintf("%T: unknown entry type %T", r, entry))
			}

			select {
			case out <- event:
			case <-ctx.Done():
				// Subscriber cancelled or resource is shutting down. We're not requiring
				// the subscriber to drain the channel, so we're marking the event done here
				// and not sending it. Will keep going until queue has been drained.
				event.Done(nil)
			}
		}
	}()

	// Fork a goroutine to wait for either the subscriber cancelling or the resource
	// shutting down.
	r.wg.Add(1)
	go func() {
		defer r.wg.Done()
		select {
		case <-r.ctx.Done():
		case <-ctx.Done():
		}
		r.mu.Lock()
		delete(r.queues, subId)
		r.mu.Unlock()
		subCancel()
		queue.ShutDownWithDrain()
	}()

	return out
}

// keyQueue wraps the workqueue to implement the error retry logic for a single subscriber,
// e.g. it implements the eventDone() method called by Event[T].Done().
type keyQueue struct {
	workqueue.RateLimitingInterface
	errorHandler ErrorHandler
}

func (kq *keyQueue) AddSync() {
	kq.Add(syncEntry{})
}

func (kq *keyQueue) AddUpsert(key Key) {
	// The entries must be added by value and not by pointer in order for
	// them to be compared by value and not by pointer.
	kq.Add(upsertEntry{key})
}

func (kq *keyQueue) AddDelete(key Key, obj any) {
	kq.Add(deleteEntry{key, obj})
}

func (kq *keyQueue) eventDone(entry queueEntry, err error) {
	// This is based on the example found in k8s.io/client-go/examples/workqueue/main.go.

	// Mark the object as done being processed. If it was marked dirty
	// during processing, it'll be processed again.
	defer kq.Done(entry)

	if err != nil {
		numRequeues := kq.NumRequeues(entry)

		var action ErrorAction
		switch entry := entry.(type) {
		case syncEntry:
			action = kq.errorHandler(Key{}, numRequeues, err)
		case upsertEntry:
			action = kq.errorHandler(entry.key, numRequeues, err)
		case deleteEntry:
			action = kq.errorHandler(entry.key, numRequeues, err)
		default:
			panic(fmt.Sprintf("keyQueue: unhandled entry %T", entry))
		}

		switch action {
		case ErrorActionRetry:
			kq.AddRateLimited(entry)
		case ErrorActionStop:
			kq.ShutDown()
		case ErrorActionIgnore:
			kq.Forget(entry)
		default:
			panic(fmt.Sprintf("keyQueue: unknown action %q from error handler %v", action, kq.errorHandler))
		}
	} else {
		// As the object was processed successfully we can "forget" it.
		// This clears any rate limiter state associated with this object, so
		// it won't be throttled based on previous failure history.
		kq.Forget(entry)
	}
}

// queueEntry restricts the set of types we use when type-switching over the
// queue entries, so that we'll get a compiler error on impossible types.
//
// The queue entries must be kept comparable and not be pointers as we want
// to be able to coalesce multiple upsertEntry's into a single element in the
// queue.
type queueEntry interface {
	isQueueEntry()
}

type syncEntry struct{}

func (syncEntry) isQueueEntry() {}

type upsertEntry struct {
	key Key
}

func (upsertEntry) isQueueEntry() {}

type deleteEntry struct {
	key Key
	obj any
}

func (deleteEntry) isQueueEntry() {}
