// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package reflector

import (
	"context"
	"fmt"

	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/client-go/tools/cache"

	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/hive/job"
	"github.com/cilium/cilium/pkg/statedb"
	"github.com/cilium/cilium/pkg/stream"
	"github.com/cilium/cilium/pkg/time"
)

type KubernetesConfig[Obj any] struct {
	BufferSize     int                  // Maximum number of objects to commit in one transaction. Uses default if left zero.
	BufferWaitTime time.Duration        // The amount of time to wait for the buffer to fill. Uses default if left zero.
	ListerWatcher  cache.ListerWatcher  // The ListerWatcher to use to retrieve the objects
	Transform      TransformFunc[Obj]   // Optional function to transform the objects given by the ListerWatcher
	Table          statedb.RWTable[Obj] // The table to populate
}

// TransformFunc is an optional function to give to the Kubernetes source
// to transform the object returned by the ListerWatcher to the desired
// target object. If the function returns false the object is silently
// skipped.
type TransformFunc[Obj any] func(any) (obj Obj, ok bool)

const (
	DefaultBufferSize     = 64
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
// Returns a 'Source' for starting and stopping it. If the source can be started
// unconditionally, consider using [KubernetesCell] instead.
func Kubernetes[Obj any](p KubernetesParams[Obj]) Reflector[Obj] {
	tr := &k8sSource[Obj]{
		KubernetesConfig: p.Config,
		db:               p.DB,
	}
	g := p.Jobs.NewGroup(p.Scope)
	var obj Obj
	g.Add(job.OneShot(fmt.Sprintf("kubernetes-reflector[%T].run", obj), tr.run))
	return g
}

// KubernetesCell returns a cell that constructs the Kubernetes source and
// adds it to the the application lifecycle.
// For dependencies see [KubernetesParams].
func KubernetesCell[Obj any]() cell.Cell {
	return cell.Group(
		cell.ProvidePrivate(Kubernetes[Obj]),
		cell.Invoke(func(s Reflector[Obj], lc hive.Lifecycle) { lc.Append(s) }),
	)
}

type k8sSource[Obj any] struct {
	KubernetesConfig[Obj]

	db *statedb.DB
}

func (s *k8sSource[Obj]) run(ctx context.Context, health cell.HealthReporter) error {
	type entry struct {
		deleted   bool
		name      string
		namespace string
		obj       Obj
	}
	type buffer map[string]entry
	bufferSize := s.getBufferSize()
	waitTime := s.getWaitTime()
	table := s.Table

	transform := s.Transform
	if transform == nil {
		// No provided transform function, use the identity function instead.
		transform = TransformFunc[Obj](func(obj any) (Obj, bool) { return obj.(Obj), true })
	}

	// Construct a stream of K8s objects, buffered into chunks every 100 milliseconds.
	// This reduces the number of write transactions required and thus the number of times
	// readers get woken up, which results in much better overall throughput.
	src := stream.Buffer(
		k8sEventObservable(s.ListerWatcher),
		bufferSize,
		waitTime,

		// Buffer the events into a map, coalescing them by key.
		func(buf buffer, ev cacheStoreEvent) buffer {
			if buf == nil {
				buf = make(buffer, bufferSize)
			}
			var entry entry
			entry.deleted = ev.Type == cacheStoreDelete

			var key string
			if d, ok := ev.Obj.(cache.DeletedFinalStateUnknown); ok {
				key = d.Key
				entry.namespace, entry.name, _ = cache.SplitMetaNamespaceKey(d.Key)

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
			buf[key] = entry
			return buf
		},
	)

	commitBuffer := func(buf buffer) {
		txn := s.db.WriteTxn(s.Table)
		defer txn.Commit()

		for _, entry := range buf {
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
				onUpdate: func(obj any) { next(cacheStoreEvent{cacheStoreUpdate, obj}) },
				onDelete: func(obj any) { next(cacheStoreEvent{cacheStoreDelete, obj}) },
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
)

type cacheStoreEvent struct {
	Type int
	Obj  any
}

// cacheStoreListener implements the methods used by the cache reflector and
// calls the given handlers for added, updated and deleted objects.
type cacheStoreListener struct {
	onAdd, onUpdate, onDelete func(any)
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
	for _, item := range items {
		s.onAdd(item)
	}
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
