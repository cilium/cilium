// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package resource

import (
	"context"
	"sync"

	corev1 "k8s.io/api/core/v1"
	k8sRuntime "k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"

	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/lock"
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
// The subscriber can process the event synchronously with the
// Event[T].Handle function, or asynchronously by calling Event[T].Done
// once the event has been processed. On errors the object's key is requeued
// for later processing. Once maximum number of retries is reached the subscriber's
// event stream will be completed with the error from the last retry attempt.
//
// The resource is lazy, e.g. it will not start the informer until a call
// has been made to Observe() or Store().
type Resource[T k8sRuntime.Object] interface {
	stream.Observable[Event[T]]

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
//			// Use the resource:
//			newExample,
//		}),
//		...
//	)
//	func newExample(pods resource.Resource[*slim_corev1.Pod]) *Example {
//		e := &Example{...}
//		pods.Observe(e.ctx, e.onPodUpdated, e.onPodsComplete)
//		return e
//	}
//	func (e *Example) onPodUpdated(key resource.Key, pod *slim_core.Pod) error {
//		// Process event ...
//	}
//	func (e *Example) onPodsComplete(err error) {
//		// Handle error ...
//	}
//
// See also pkg/k8s/resource/example/main.go for a runnable example.
func New[T k8sRuntime.Object](lc hive.Lifecycle, lw cache.ListerWatcher, opts ...Option) Resource[T] {
	r := &resource[T]{
		queues: make(map[uint64]*keyQueue),
		needed: make(chan struct{}, 1),
		opts:   defaultOptions(),
		lw:     lw,
	}
	for _, applyOpt := range opts {
		applyOpt(&r.opts)
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

	lw   cache.ListerWatcher
	opts options

	storePromise  promise.Promise[Store[T]]
	storeResolver promise.Resolver[Store[T]]
}

var _ Resource[*corev1.Node] = &resource[*corev1.Node]{}

func (r *resource[T]) Store(ctx context.Context) (Store[T], error) {
	r.markNeeded()
	return r.storePromise.Await(ctx)
}

func (r *resource[T]) pushUpdate(key Key) {
	r.mu.RLock()
	for _, queue := range r.queues {
		queue.AddUpdate(key)
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

func (r *resource[T]) Start(startCtx hive.HookContext) error {
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

	r.wg.Add(1)
	go func() {
		defer r.wg.Done()
		informer.Run(r.ctx.Done())
	}()

	// Wait for cache to be synced before resolving the store
	if !cache.WaitForCacheSync(r.ctx.Done(), informer.HasSynced) {
		// The context is cancelled when stopping and all dependees of Resource[T] are
		// stopped before it, but to be safe, resolve the store with nil to catch
		// misbehaving dependees.
		r.storeResolver.Reject(r.ctx.Err())
	} else {
		r.storeResolver.Resolve(&typedStore[T]{store})
	}
}

func (r *resource[T]) Stop(stopCtx hive.HookContext) error {
	r.cancel()
	r.wg.Wait()
	return nil
}

func (r *resource[T]) Observe(subCtx context.Context, next func(Event[T]), complete func(error)) {
	r.markNeeded()

	subCtx, subCancel := context.WithCancel(subCtx)

	queue := &keyQueue{
		RateLimitingInterface: workqueue.NewRateLimitingQueue(r.opts.rateLimiter()),
		errorHandler:          r.opts.errorHandler,
	}
	r.mu.Lock()
	subId := r.subId
	r.subId++
	r.mu.Unlock()

	// Fork a goroutine to pop elements from the queue and pass them to the subscriber.
	r.wg.Add(1)
	go func() {
		defer r.wg.Done()

		// Make sure to call ShutDown() in the end. Calling ShutDownWithDrain is not
		// enough as DelayingQueue does not implement it, so without ShutDown() we'd
		// leak the (*delayingType).waitingLoop.
		defer queue.ShutDown()

		// Wait for the store so we can emit the initial items and the sync event.
		store, err := r.storePromise.Await(subCtx)
		if err != nil {
			complete(err)
			return
		}

		r.mu.Lock()
		r.queues[subId] = queue

		// Append the initial set of keys to the queue + sentinel for the sync event.
		// We go through the queue instead of directly emitting to avoid a race between
		// the queue add and listing keys, plus to have one error handling path for Event.Done().
		keyIter := store.IterKeys()
		for keyIter.Next() {
			queue.AddUpdate(keyIter.Key())
		}
		queue.AddSync()
		r.mu.Unlock()

		for {
			// Retrieve an item from the subscribers queue and then fetch the object
			// from the store.
			raw, shutdown := queue.Get()
			if shutdown {
				break
			}
			entry := raw.(queueEntry)
			baseEvent := baseEvent{
				func(err error) { queue.eventDone(entry, err) },
			}
			switch entry := entry.(type) {
			case syncEntry:
				next(&SyncEvent[T]{baseEvent})
			case deleteEntry:
				next(&DeleteEvent[T]{baseEvent, entry.key, entry.obj.(T)})
			case updateEntry:
				obj, exists, err := store.GetByKey(entry.key)
				if err != nil {
					queue.setError(err)
					break
				}
				// Emit the update event if the item exists, if it doesn't, then
				// it has been deleted and a delete will follow soon.
				if exists {
					next(&UpdateEvent[T]{baseEvent, entry.key, obj})
				}
			}
		}
		r.mu.Lock()
		delete(r.queues, subId)
		r.mu.Unlock()
		complete(queue.getError())
	}()

	// Fork a goroutine to wait for either the subscriber cancelling or the resource
	// shutting down.
	r.wg.Add(1)
	go func() {
		defer r.wg.Done()
		select {
		case <-r.ctx.Done():
		case <-subCtx.Done():
		}
		subCancel()
		queue.ShutDownWithDrain()
	}()
}

// keyQueue wraps the workqueue to implement the error retry logic for a single subscriber,
// e.g. it implements the eventDone() method called by Event[T].Done().
type keyQueue struct {
	lock.Mutex
	err error

	workqueue.RateLimitingInterface
	errorHandler ErrorHandler
}

func (kq *keyQueue) AddSync() {
	kq.Add(syncEntry{})
}

func (kq *keyQueue) AddUpdate(key Key) {
	// The entries must be added by value and not by pointer in order for
	// them to be compared by value and not by pointer.
	kq.Add(updateEntry{key})
}

func (kq *keyQueue) AddDelete(key Key, obj any) {
	kq.Add(deleteEntry{key, obj})
}

func (kq *keyQueue) getError() error {
	kq.Lock()
	defer kq.Unlock()
	return kq.err
}

func (kq *keyQueue) setError(err error) {
	kq.Lock()
	defer kq.Unlock()
	if kq.err == nil {
		kq.err = err
	}
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
			action = ErrorActionStop
		case updateEntry:
			action = kq.errorHandler(entry.key, numRequeues, err)
		case deleteEntry:
			action = kq.errorHandler(entry.key, numRequeues, err)
		}

		switch action {
		case ErrorActionRetry:
			go kq.AddRateLimited(entry)
		case ErrorActionStop:
			kq.setError(err)
			kq.ShutDown()
		case ErrorActionIgnore:
			kq.Forget(entry)
		}
	} else {
		// As the object was processed successfully we can "forget" it.
		// This clears any rate limiter state associated with this object, so
		// it won't be throttled based on previous failure history.
		kq.Forget(entry)
	}
}

type queueEntry interface {
	isQueueEntry()
}

type syncEntry struct{}

func (syncEntry) isQueueEntry() {}

type updateEntry struct {
	key Key
}

func (updateEntry) isQueueEntry() {}

type deleteEntry struct {
	key Key
	obj any
}

func (deleteEntry) isQueueEntry() {}
