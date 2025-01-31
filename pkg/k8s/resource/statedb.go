// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package resource

import (
	"context"
	"fmt"
	"runtime"

	"github.com/cilium/statedb"
	"github.com/cilium/stream"
	k8sRuntime "k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/util/workqueue"

	"github.com/cilium/cilium/pkg/rate"
	"github.com/cilium/cilium/pkg/time"
)

// NewTableEventStream constructs a stream of [Event] from a StateDB table of Kubernetes
// objects. This is meant as a transitionary mechanism for converting from Resource[T] to Table[T]
// and is not meant as a long term solution. Sub-systems should instead consider either moving to
// the StateDB reconciler (expressing their desired state in a StateDB table) or using an internal
// workqueue for processing.
//
// This should only be used when the workqueue retry handling is required. If it is not needed
// you should use [statedb.Observable].
//
// Deprecated: This is a transitionary helper. Use only if converting from Resource[T] and need the
// workqueue retry handling. If retrying is not needed use [statedb.Observable] instead or refactor
// your code to use [statedb.Table.Changes].
func NewTableEventStream[T k8sRuntime.Object](db *statedb.DB, table statedb.Table[T], getByKey func(Key) statedb.Query[T]) stream.Observable[Event[T]] {
	return &tableWorkQueue[T]{
		db:       db,
		table:    table,
		getByKey: getByKey,
	}
}

type tableWorkQueueItem struct {
	key          Key
	initOccurred bool
}

type tableWorkQueue[T k8sRuntime.Object] struct {
	db       *statedb.DB
	table    statedb.Table[T]
	getByKey func(Key) statedb.Query[T]
}

func (twq *tableWorkQueue[T]) Observe(ctx context.Context, next func(Event[T]), complete func(error)) {
	var zero T
	wq := workqueue.NewTypedRateLimitingQueueWithConfig[tableWorkQueueItem](
		workqueue.DefaultTypedControllerRateLimiter[tableWorkQueueItem](),
		workqueue.TypedRateLimitingQueueConfig[tableWorkQueueItem]{
			Name: fmt.Sprintf("%T", zero),
		},
	)

	var deletedObjects lastKnownObjects[T]

	wtxn := twq.db.WriteTxn(twq.table)
	changeIter, err := twq.table.Changes(wtxn)
	_, initWatch := twq.table.Initialized(wtxn)
	wtxn.Commit()
	if err != nil {
		complete(err)
		return
	}

	_, callerFile, callerLine, _ := runtime.Caller(1)
	debugInfo := fmt.Sprintf("%T.Observe() called from %s:%d", twq, callerFile, callerLine)
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

	// Start a goroutine to feed the workqueue.
	go func() {
		defer wq.ShutDown()

		// Limit the read transaction rate to at most 10 per second to reduce
		// overhead and coalesce changes.
		limiter := rate.NewLimiter(time.Second/10, 1)
		defer limiter.Stop()

		for {
			changes, watch := changeIter.Next(twq.db.ReadTxn())
			for change := range changes {
				if ctx.Err() != nil {
					break
				}
				obj := change.Object
				key := NewKey(obj)
				wq.Add(tableWorkQueueItem{key: key})
				if change.Deleted {
					deletedObjects.Store(key, change.Object)
				}
			}
			select {
			case <-ctx.Done():
				return
			case <-watch:
			case <-initWatch:
				initWatch = nil
				wq.Add(tableWorkQueueItem{
					initOccurred: true,
				})
			}
			if err := limiter.Wait(ctx); err != nil {
				return
			}
		}
	}()

	// And a goroutine to emit the events
	go func() {
		defer complete(nil)

		for {
			item, shutdown := wq.Get()
			if shutdown {
				return
			}

			var event Event[T]
			var eventDoneSentinel = new(bool)
			event.Done = func(err error) {
				runtime.SetFinalizer(eventDoneSentinel, nil)
				defer wq.Done(item)
				if err == nil {
					// Clear rate limiting.
					wq.Forget(item)

					if event.Kind == Delete {
						// Deletion processed successfully, forget the deleted object.
						deletedObjects.DeleteByUID(item.key, event.Object)
					}
				} else {
					// Requeue for retry.
					wq.AddRateLimited(item)
				}
			}
			// Add a finalizer to catch forgotten calls to Done().
			runtime.SetFinalizer(eventDoneSentinel, doneFinalizer)

			if item.initOccurred {
				event.Kind = Sync
				next(event)
				continue
			}

			obj, _, found := twq.table.Get(twq.db.ReadTxn(), twq.getByKey(item.key))
			if found {
				event.Kind = Upsert
				event.Object = obj
				next(event)
			} else {
				event.Kind = Delete
				obj, found := deletedObjects.Load(item.key)
				if found {
					event.Object = obj
					next(event)
				}
			}
		}
	}()
}
