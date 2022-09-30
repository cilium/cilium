// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package resource

import (
	"context"
	"sync"

	"go.uber.org/fx"
	corev1 "k8s.io/api/core/v1"
	k8sRuntime "k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"

	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
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
// Resource is provided to the hive via NewResourceConstructor.
type Resource[T k8sRuntime.Object] interface {
	stream.Observable[Event[T]]

	// Store retrieves the read-only store for the resource. Blocks until
	// the store has been synchronized or the context cancelled.
	// Returns a non-nil error if context is cancelled or the resource
	// has been stopped before store has synchronized.
	Store(context.Context) (Store[T], error)
}

// NewResourceConstructor provides a constructor for Resource when given a function
// that maps from a Clientset into a ListerWatcher:
//
//	var exampleCell = hive.NewCell(
//		"example",
//	 	fx.Provide(
//		 	// Provide `Resource[*slim_corev1.Pod]` to the hive:
//	 		resource.NewResourceConstructor(
//	 			func(c k8sClient.Clientset) cache.ListerWatcher {
//					return utils.ListerWatcherFromTyped[*slim_corev1.PodList](
//						c.Slim().CoreV1().Pods(""),
//					)
//				}),
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
// See also pkg/k8s/resource/example/main.go.
func NewResourceConstructor[T k8sRuntime.Object](lw func(c k8sClient.Clientset) cache.ListerWatcher) func(lc fx.Lifecycle, c k8sClient.Clientset) Resource[T] {
	return NewResourceConstructorWithRateLimiter[T](workqueue.DefaultControllerRateLimiter(), lw)
}

// NewResourceConstructorWithRateLimiter is the same as NewResourceConstructor, but with a custom rate limiter.
func NewResourceConstructorWithRateLimiter[T k8sRuntime.Object](rateLimiter workqueue.RateLimiter, lw func(c k8sClient.Clientset) cache.ListerWatcher) func(lc fx.Lifecycle, c k8sClient.Clientset) Resource[T] {
	return func(lc fx.Lifecycle, c k8sClient.Clientset) Resource[T] {
		if !c.IsEnabled() {
			return nil
		}
		newLW := func() cache.ListerWatcher { return lw(c) }
		res := newResource[T](newLW, rateLimiter)
		lc.Append(fx.Hook{OnStart: res.start, OnStop: res.stop})
		return res
	}
}

// defaultMaxRetries is the default number of retries for processing an event that was marked
// failed by a non-nil error to Done().
const defaultMaxRetries = 5

type resource[T k8sRuntime.Object] struct {
	mu     lock.RWMutex
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	queues map[uint64]*keyQueue
	subId  uint64

	rateLimiter     workqueue.RateLimiter
	maxEventRetries int

	storePromise  promise.Promise[Store[T]]
	storeResolver promise.Resolver[Store[T]]

	// newLW is the constructor for the ListerWatcher. It's invoked only when starting as the
	// Clientset is not usable before it has been started.
	newLW func() cache.ListerWatcher
}

var _ Resource[*corev1.Node] = &resource[*corev1.Node]{}

func newResource[T k8sRuntime.Object](newLW func() cache.ListerWatcher, rateLimiter workqueue.RateLimiter) *resource[T] {
	r := &resource[T]{
		newLW:           newLW,
		queues:          make(map[uint64]*keyQueue),
		maxEventRetries: defaultMaxRetries,
		rateLimiter:     rateLimiter,
	}
	r.ctx, r.cancel = context.WithCancel(context.Background())
	r.storeResolver, r.storePromise = promise.New[Store[T]]()
	return r
}

func (r *resource[T]) Store(ctx context.Context) (Store[T], error) {
	return r.storePromise.Await(ctx)
}

func (r *resource[T]) pushUpdate(key Key) {
	r.mu.RLock()
	for _, queue := range r.queues {
		queue.Add(&updateEntry{key})
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
		queue.Add(&deleteEntry{key, obj})
	}
	r.mu.RUnlock()
}

func (r *resource[T]) start(startCtx context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	var objType T
	handlerFuncs :=
		cache.ResourceEventHandlerFuncs{
			AddFunc:    func(obj any) { r.pushUpdate(NewKey(obj)) },
			UpdateFunc: func(old any, new any) { r.pushUpdate(NewKey(new)) },
			DeleteFunc: func(obj any) { r.pushDelete(obj) },
		}

	store, informer := cache.NewInformer(r.newLW(), objType, 0, handlerFuncs)

	r.wg.Add(2)
	go func() {
		defer r.wg.Done()
		informer.Run(r.ctx.Done())
	}()
	go func() {
		defer r.wg.Done()

		// Wait for cache to be synced before resolving the store
		if !cache.WaitForCacheSync(r.ctx.Done(), informer.HasSynced) {
			// The context is cancelled when stopping and all dependees of Resource[T] are
			// stopped before it, but to be safe, resolve the store with nil to catch
			// misbehaving dependees.
			r.storeResolver.Reject(r.ctx.Err())
			return
		}
		r.storeResolver.Resolve(&typedStore[T]{store})
	}()

	return nil
}

func (r *resource[T]) stop(stopCtx context.Context) error {
	r.cancel()
	r.wg.Wait()
	return nil
}

func (r *resource[T]) Observe(subCtx context.Context, next func(Event[T]), complete func(error)) {
	subCtx, subCancel := context.WithCancel(subCtx)

	queue := &keyQueue{
		RateLimitingInterface: workqueue.NewRateLimitingQueue(workqueue.DefaultControllerRateLimiter()),
		maxRetries:            r.maxEventRetries,
	}

	// Fork a goroutine to pop elements from the queue and pass them to the subscriber.
	r.wg.Add(1)
	go func() {
		defer r.wg.Done()
		defer subCancel()

		// Wait for the store so we can emit the initial items and the sync event.
		store, err := r.storePromise.Await(subCtx)
		if err != nil {
			complete(err)
			return
		}

		r.mu.Lock()
		r.subId++
		r.queues[r.subId] = queue

		// Append the initial set of keys to the queue + sentinel for the sync event.
		// We go through the queue instead of directly emitting to avoid a race between
		// the queue add and listing keys, plus to have one error handling path for Event.Done().
		keyIter := store.IterKeys()
		for keyIter.Next() {
			queue.Add(&updateEntry{keyIter.Key()})
		}
		queue.Add(&syncEntry{})
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
			case *syncEntry:
				next(&SyncEvent[T]{baseEvent, store})
			case *deleteEntry:
				next(&DeleteEvent[T]{baseEvent, entry.key, entry.obj.(T)})
			case *updateEntry:
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
		delete(r.queues, r.subId)
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
			subCancel()
		case <-subCtx.Done():
		}
		queue.ShutDownWithDrain()
	}()
}

// keyQueue wraps the workqueue to implement the error retry logic for a single subscriber,
// e.g. it implements the eventDone() method called by Event[T].Done().
type keyQueue struct {
	lock.Mutex
	workqueue.RateLimitingInterface

	maxRetries int
	err        error
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
		// Processing of this item failed. Check if retry limit has been reached.
		if kq.NumRequeues(entry) >= kq.maxRetries-1 {
			kq.setError(err)
			kq.ShutDown()
			return
		}

		// Can still retry processing it. Add it back to the queue
		// after a delay.
		go kq.AddRateLimited(entry)
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
