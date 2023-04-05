// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package k8s

import (
	"context"
	"fmt"
	"time"

	"github.com/hashicorp/go-memdb"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/cache"

	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/statedb"
	"github.com/cilium/cilium/pkg/stream"
)

type tableReflectorParams[Obj tableObjectConstraints[Obj]] struct {
	cell.In

	Lifecycle     hive.Lifecycle
	DB            statedb.DB
	Table         statedb.Table[Obj]
	ListerWatcher cache.ListerWatcher
}

type tableObjectConstraints[Obj any] interface {
	statedb.ObjectConstraints[Obj]
	runtime.Object
}

func NewK8sTableCell[Obj tableObjectConstraints[Obj]](
	name string,
	listerWatcherProvider any, // func(...) cache.ListerWatcher.
	extraIndexes ...*memdb.IndexSchema,
) cell.Cell {
	// FIXME rethink the API. listerWatcherProvider is pretty ugly. Perhaps
	// caller should do cell.Module and ProvidePrivate the ListerWatcher and
	// here we'd just do cell.Group with the invoke and NewTableCell.
	return cell.Module(
		"k8s-table-"+name,
		fmt.Sprintf("Reflects Kubernetes objects to table %s", name),

		statedb.NewReadOnlyTableCell[Obj](tableSchema(name, extraIndexes)),
		cell.ProvidePrivate(listerWatcherProvider),
		cell.Invoke(registerTableReflector[Obj]),
	)
}

var (
	idIndex = &memdb.IndexSchema{
		Name:         "id",
		AllowMissing: false,
		Unique:       true,
		Indexer: &memdb.CompoundIndex{
			Indexes: []memdb.Indexer{
				&memdb.StringFieldIndex{Field: "Namespace"},
				&memdb.StringFieldIndex{Field: "Name"},
			},
			AllowMissing: true,
		},
	}

	namespaceIndex = &memdb.IndexSchema{
		Name:         "namespace",
		AllowMissing: true,
		Unique:       false,
		Indexer:      &memdb.StringFieldIndex{Field: "Namespace"},
	}
)

func tableSchema(name string, extraIndexes []*memdb.IndexSchema) *memdb.TableSchema {
	indexes := map[string]*memdb.IndexSchema{
		"id":        idIndex,
		"namespace": namespaceIndex,
	}

	for _, idx := range extraIndexes {
		indexes[idx.Name] = idx
	}

	return &memdb.TableSchema{Name: name, Indexes: indexes}
}

func registerTableReflector[Obj tableObjectConstraints[Obj]](p tableReflectorParams[Obj]) {
	tr := &tableReflector[Obj]{params: p}
	p.Lifecycle.Append(tr)
}

type tableReflector[Obj tableObjectConstraints[Obj]] struct {
	params tableReflectorParams[Obj]
}

func (tr *tableReflector[Obj]) Start(hive.HookContext) error {
	go tr.synchronize()
	return nil
}

func (tr *tableReflector[Obj]) Stop(hive.HookContext) error {
	return nil
}

func (tr *tableReflector[Obj]) synchronize() {
	type entry struct {
		deleted   bool
		name      string
		namespace string
		obj       Obj
	}
	type buffer map[string]entry
	const bufferSize = 64 // TODO benchmark to figure out appropriate size
	const waitTime = 100 * time.Millisecond

	src := stream.BufferBy(
		k8sEventObservable(tr.params.ListerWatcher),
		bufferSize,
		waitTime,

		// Buffer the events into a map, coalescing them by key.
		func(buf buffer, ev cacheStoreEvent) buffer {
			if buf == nil {
				buf = make(buffer, bufferSize)
			}
			var entry entry
			if ev.Type == cacheStoreDelete {
				entry.deleted = true
			} else {
				var ok bool
				entry.obj, ok = ev.Obj.(Obj)
				if !ok {
					panic(fmt.Sprintf("%T internal error: Object %T not of correct type", tr, ev.Obj))
				}
			}
			var key string
			if d, ok := ev.Obj.(cache.DeletedFinalStateUnknown); ok {
				key = d.Key
				entry.namespace, entry.name, _ = cache.SplitMetaNamespaceKey(d.Key)
			} else {
				meta, err := meta.Accessor(ev.Obj)
				if err != nil {
					panic(fmt.Sprintf("%T internal error: meta.Accessor failed: %s", tr, err))
				}
				entry.name = meta.GetName()
				if ns := meta.GetNamespace(); ns != "" {
					key = ns + "/" + meta.GetName()
					entry.namespace = ns
				} else {
					key = meta.GetName()
				}
			}
			buf[key] = entry
			return buf
		},

		// Reset by allocating a new buffer.
		func(buffer) buffer {
			return make(buffer, bufferSize)
		},
	)

	commitBuffer := func(buf buffer) {
		txn := tr.params.DB.WriteTxn()
		writer := tr.params.Table.Writer(txn)
		for _, entry := range buf {
			if !entry.deleted {
				if err := writer.Insert(entry.obj); err != nil {
					// TODO bad schema, how do we want to fail?
					panic(err)
				}
			} else {
				obj, err := writer.First(ByName(entry.namespace, entry.name))
				if err != nil {
					// TODO bad schema, how do we want to fail?
					panic(err)
				}
				if err := writer.Delete(obj); err != nil {
					// TODO bad schema, how do we want to fail?
					panic(err)
				}
			}
		}
		if err := txn.Commit(); err != nil {
			// TODO commit hook may reject this. how do we want to fail?
			panic(err)
		}
	}

	src.Observe(
		context.TODO(),
		commitBuffer,
		func(err error) {},
	)

}

func ByName(namespace string, name string) statedb.Query {
	return statedb.Query{Index: "id", Args: []any{namespace, name}}
}

func ByNamespace(namespace string) statedb.Query {
	return statedb.Query{Index: "namespace", Args: []any{namespace}}
}

var _ hive.HookInterface = (*tableReflector[*v1.Node])(nil)

// k8sEventObservable turns a ListerWatcher into an observable using the client-go's Reflector.
// TODO: catch watch errors and log or update metrics. Emit watch error as event?
func k8sEventObservable(lw cache.ListerWatcher) stream.Observable[cacheStoreEvent] {
	return stream.FuncObservable[cacheStoreEvent](
		func(ctx context.Context, next func(cacheStoreEvent), complete func(err error)) {
			store := &cacheStoreListener{
				onAdd:    func(obj any) { next(cacheStoreEvent{cacheStoreAdd, obj}) },
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
		s.onUpdate(item)
	}
	return nil
}

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
