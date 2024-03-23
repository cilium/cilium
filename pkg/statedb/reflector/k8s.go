// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package reflector

import (
	"context"
	"fmt"

	"github.com/cilium/stream"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/client-go/tools/cache"

	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/hive/job"
	"github.com/cilium/cilium/pkg/statedb"
	"github.com/cilium/cilium/pkg/time"
)

type KubernetesConfig[Obj any] struct {
	BufferSize     int                  // Maximum number of objects to commit in one transaction. Uses default if left zero.
	BufferWaitTime time.Duration        // The amount of time to wait for the buffer to fill. Uses default if left zero.
	ListerWatcher  cache.ListerWatcher  // The ListerWatcher to use to retrieve the objects
	Transform      TransformFunc[Obj]   // Optional function to transform the objects given by the ListerWatcher
	QueryAll       QueryAllFunc[Obj]    // Optional function to query all objects
	Table          statedb.RWTable[Obj] // The table to populate
}

// TransformFunc is an optional function to give to the Kubernetes reflector
// to transform the object returned by the ListerWatcher to the desired
// target object. If the function returns false the object is silently
// skipped.
type TransformFunc[Obj any] func(any) (obj Obj, ok bool)

// QueryAllFunc is an optional function to give to the Kubernetes reflector
// to query all objects in the table that are managed by the reflector.
// It is used to delete all objects when the underlying cache.Reflector needs
// to Replace() all items for a resync.
type QueryAllFunc[Obj any] func(statedb.ReadTxn, statedb.Table[Obj]) statedb.Iterator[Obj]

const (
	// DefaultBufferSize is the maximum number of objects to commit to the table in one write transaction.
	DefaultBufferSize = 64

	// DefaultBufferWaitTime is the amount of time to wait to fill the buffer before committing objects.
	DefaultBufferWaitTime = 50 * time.Millisecond
)

func (cfg KubernetesConfig[Obj]) getBufferSize() int {
	if cfg.BufferSize == 0 {
		return DefaultBufferSize
	}
	return cfg.BufferSize
}

func (cfg KubernetesConfig[Obj]) getWaitTime() time.Duration {
	if cfg.BufferWaitTime == 0 {
		return DefaultBufferWaitTime
	}
	return cfg.BufferWaitTime
}

type KubernetesParams[Obj any] struct {
	cell.In

	Config KubernetesConfig[Obj]
	Jobs   job.Registry
	Scope  cell.Scope
	DB     *statedb.DB
}

// Kubernetes synchronizes statedb table with an external Kubernetes resource.
// Returns a 'Reflector' for starting and stopping it. If the source can be started
// unconditionally, consider using [KubernetesCell] instead.
func Kubernetes[Obj any](p KubernetesParams[Obj]) Reflector[Obj] {
	tr := &k8sReflector[Obj]{
		KubernetesConfig: p.Config,
		db:               p.DB,
	}
	g := p.Jobs.NewGroup(p.Scope)
	g.Add(job.OneShot(
		fmt.Sprintf("k8s-reflector-[%T]", *new(Obj)),
		tr.run))
	return g
}

// KubernetesCell constructs a cell that constructs a Kubernetes source and
// adds it to the application lifecycle. If you need dynamic control
// over if and when to start or stop the reflection, use [Kubernetes] and
// call Reflector.Start and Reflector.Stop manually.
//
// For dependencies needed by this cell see [KubernetesParams].
func KubernetesCell[Obj any]() cell.Cell {
	return cell.Group(
		cell.ProvidePrivate(Kubernetes[Obj]),
		cell.Invoke(func(s Reflector[Obj], lc cell.Lifecycle) {
			lc.Append(s)
		}),
	)
}

type k8sReflector[Obj any] struct {
	KubernetesConfig[Obj]

	db *statedb.DB
}

func (s *k8sReflector[Obj]) run(ctx context.Context, health cell.HealthReporter) error {
	type entry struct {
		deleted   bool
		name      string
		namespace string
		obj       Obj
	}
	type buffer struct {
		replaceItems []any
		entries      map[string]entry
	}
	bufferSize := s.getBufferSize()
	waitTime := s.getWaitTime()
	table := s.Table

	transform := s.Transform
	if transform == nil {
		// No provided transform function, use the identity function instead.
		transform = TransformFunc[Obj](func(obj any) (Obj, bool) { return obj.(Obj), true })
	}

	queryAll := s.QueryAll
	if queryAll == nil {
		// No query function provided, use All()
		queryAll = QueryAllFunc[Obj](func(txn statedb.ReadTxn, tbl statedb.Table[Obj]) statedb.Iterator[Obj] {
			iter, _ := tbl.All(txn)
			return iter
		})
	}

	// Construct a stream of K8s objects, buffered into chunks every [waitTime] period
	// and then committed.
	// This reduces the number of write transactions required and thus the number of times
	// readers get woken up, which results in much better overall throughput.
	src := stream.Buffer(
		k8sEventObservable(s.ListerWatcher),
		bufferSize,
		waitTime,

		// Buffer the events into a map, coalescing them by key.
		func(buf *buffer, ev cacheStoreEvent) *buffer {
			switch {
			case ev.Type == cacheStoreReplace:
				return &buffer{
					replaceItems: ev.Obj.([]any),
					entries:      make(map[string]entry, bufferSize), // Forget prior entries
				}
			case buf == nil:
				buf = &buffer{
					replaceItems: nil,
					entries:      make(map[string]entry, bufferSize),
				}
			}

			var entry entry
			entry.deleted = ev.Type == cacheStoreDelete

			var key string
			if d, ok := ev.Obj.(cache.DeletedFinalStateUnknown); ok {
				key = d.Key
				var err error
				entry.namespace, entry.name, err = cache.SplitMetaNamespaceKey(d.Key)
				if err != nil {
					panic(fmt.Sprintf("%T internal error: cache.SplitMetaNamespaceKey(%q) failed: %s", s, d.Key, err))
				}
				entry.obj, ok = transform(d.Obj)
				if !ok {
					return buf
				}
			} else {
				meta, err := meta.Accessor(ev.Obj)
				if err != nil {
					panic(fmt.Sprintf("%T internal error: meta.Accessor failed: %s", s, err))
				}
				entry.name = meta.GetName()
				if ns := meta.GetNamespace(); ns != "" {
					key = ns + "/" + meta.GetName()
					entry.namespace = ns
				} else {
					key = meta.GetName()
				}

				var ok bool
				entry.obj, ok = transform(ev.Obj)
				if !ok {
					return buf
				}
			}
			buf.entries[key] = entry
			return buf
		},
	)

	commitBuffer := func(buf *buffer) {
		txn := s.db.WriteTxn(s.Table)
		defer txn.Commit()

		if buf.replaceItems != nil {
			iter := queryAll(txn, table)
			for obj, _, ok := iter.Next(); ok; obj, _, ok = iter.Next() {
				table.Delete(txn, obj)
			}
			for _, item := range buf.replaceItems {
				table.Insert(txn, item.(Obj))
			}
		}

		for _, entry := range buf.entries {
			if !entry.deleted {
				table.Insert(txn, entry.obj)
			} else {
				table.Delete(txn, entry.obj)
			}
		}
	}

	errs := make(chan error)
	src.Observe(
		ctx,
		commitBuffer,
		func(err error) {
			errs <- err
			close(errs)
		},
	)
	return <-errs
}

// k8sEventObservable turns a ListerWatcher into an observable using the client-go's Reflector.
func k8sEventObservable(lw cache.ListerWatcher) stream.Observable[cacheStoreEvent] {
	return stream.FuncObservable[cacheStoreEvent](
		func(ctx context.Context, next func(cacheStoreEvent), complete func(err error)) {
			store := &cacheStoreListener{
				onAdd: func(obj any) {
					next(cacheStoreEvent{cacheStoreAdd, obj})
				},
				onUpdate:  func(obj any) { next(cacheStoreEvent{cacheStoreUpdate, obj}) },
				onDelete:  func(obj any) { next(cacheStoreEvent{cacheStoreDelete, obj}) },
				onReplace: func(objs []any) { next(cacheStoreEvent{cacheStoreReplace, objs}) },
			}
			reflector := cache.NewReflector(lw, nil, store, 0)
			go func() {
				reflector.Run(ctx.Done())
				complete(nil)
			}()
		})
}

const (
	cacheStoreAdd = iota
	cacheStoreUpdate
	cacheStoreDelete
	cacheStoreReplace
)

type cacheStoreEvent struct {
	Type int
	Obj  any
}

// cacheStoreListener implements the methods used by the cache reflector and
// calls the given handlers for added, updated and deleted objects.
type cacheStoreListener struct {
	onAdd, onUpdate, onDelete func(any)
	onReplace                 func([]any)
}

func (s *cacheStoreListener) Add(obj interface{}) error {
	s.onAdd(obj)
	return nil
}

func (s *cacheStoreListener) Update(obj interface{}) error {
	s.onUpdate(obj)
	return nil
}

func (s *cacheStoreListener) Delete(obj interface{}) error {
	s.onDelete(obj)
	return nil
}

func (s *cacheStoreListener) Replace(items []interface{}, resourceVersion string) error {
	if items == nil {
		// Always emit a non-nil slice for replace.
		items = []interface{}{}
	}
	s.onReplace(items)
	return nil
}

// These methods are never called by cache.Reflector:

func (*cacheStoreListener) Get(obj interface{}) (item interface{}, exists bool, err error) {
	panic("unimplemented")
}
func (*cacheStoreListener) GetByKey(key string) (item interface{}, exists bool, err error) {
	panic("unimplemented")
}
func (*cacheStoreListener) List() []interface{} { panic("unimplemented") }
func (*cacheStoreListener) ListKeys() []string  { panic("unimplemented") }
func (*cacheStoreListener) Resync() error       { panic("unimplemented") }

var _ cache.Store = &cacheStoreListener{}
