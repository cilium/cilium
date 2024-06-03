// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package resource

import (
	"context"
	"time"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"
	"github.com/cilium/statedb/index"
	"github.com/cilium/stream"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/cache"
)

func newKeyIndex[T runtime.Object]() statedb.Index[T, Key] {
	return statedb.Index[T, Key]{
		Name: "key",
		FromObject: func(obj T) index.KeySet {
			return index.NewKeySet(index.String(NewKey(obj).String()))
		},
		FromKey: index.Stringer[Key],
		Unique:  true,
	}
}

// statedbStore implements cache.Store with a StateDB table for
// reading.
type statedbStore[T runtime.Object] struct {
	db       *statedb.DB
	table    statedb.RWTable[T]
	keyIndex statedb.Index[T, Key]
}

// AddIndexers implements cache.Indexer.
func (s *statedbStore[T]) AddIndexers(newIndexers cache.Indexers) error {
	panic("unimplemented")
}

// ByIndex implements cache.Indexer.
func (s *statedbStore[T]) ByIndex(indexName string, indexedValue string) ([]interface{}, error) {
	panic("unimplemented")
}

// GetIndexers implements cache.Indexer.
func (s *statedbStore[T]) GetIndexers() cache.Indexers {
	panic("unimplemented")
}

// Index implements cache.Indexer.
func (s *statedbStore[T]) Index(indexName string, obj interface{}) ([]interface{}, error) {
	panic("unimplemented")
}

// IndexKeys implements cache.Indexer.
func (s *statedbStore[T]) IndexKeys(indexName string, indexedValue string) ([]string, error) {
	panic("unimplemented")
}

// ListIndexFuncValues implements cache.Indexer.
func (s *statedbStore[T]) ListIndexFuncValues(indexName string) []string {
	panic("unimplemented")
}

// Add implements cache.Store.
func (s *statedbStore[T]) Add(obj interface{}) error {
	panic("not supported")
}

// Delete implements cache.Store.
func (s *statedbStore[T]) Delete(obj interface{}) error {
	panic("not supported")
}

// Get implements cache.Store.
func (s *statedbStore[T]) Get(obj interface{}) (item interface{}, exists bool, err error) {
	result, _, exists := s.table.Get(s.db.ReadTxn(), s.keyIndex.QueryFromObject(obj.(T)))
	return result, exists, nil
}

// GetByKey implements cache.Store.
func (s *statedbStore[T]) GetByKey(key string) (item interface{}, exists bool, err error) {
	objName, err := cache.ParseObjectName(key)
	if err != nil {
		return nil, false, err
	}
	result, _, exists := s.table.Get(s.db.ReadTxn(), s.keyIndex.Query(objName))
	return result, exists, nil
}

// List implements cache.Store.
func (s *statedbStore[T]) List() []interface{} {
	txn := s.db.ReadTxn()
	objs := make([]any, 0, s.table.NumObjects(txn))
	iter, _ := s.table.All(txn)
	for obj, _, ok := iter.Next(); ok; obj, _, ok = iter.Next() {
		objs = append(objs, obj)
	}
	return objs
}

// ListKeys implements cache.Store.
func (s *statedbStore[T]) ListKeys() []string {
	txn := s.db.ReadTxn()
	keys := make([]string, 0, s.table.NumObjects(txn))
	iter, _ := s.table.All(txn)
	for obj, _, ok := iter.Next(); ok; obj, _, ok = iter.Next() {
		objName, err := cache.ObjectToName(obj)
		if err == nil {
			keys = append(keys, objName.String())
		}
	}
	return keys
}

// Replace implements cache.Store.
func (s *statedbStore[T]) Replace([]interface{}, string) error {
	panic("not supported")
}

// Resync implements cache.Store.
func (s *statedbStore[T]) Resync() error {
	panic("not supported")
}

// Update implements cache.Store.
func (s *statedbStore[T]) Update(obj interface{}) error {
	panic("not supported")
}

var _ cache.Indexer = &statedbStore[*runtime.Unknown]{}

type Params struct {
	cell.In

	JobGroup job.Group
	DB       *statedb.DB
}

func NewTableResource[T runtime.Object](name string, lw cache.ListerWatcher, params Params, opts ...ResourceOption) (statedb.Table[T], statedb.Index[T, Key], Resource[T]) {
	index := newKeyIndex[T]()
	table, err := statedb.NewTable(
		"k8s-"+name,
		index,
	)
	if err != nil {
		panic(err)
	}
	err = params.DB.RegisterTable(table)
	if err != nil {
		panic(err)
	}
	store := &typedStore[T]{
		store: &statedbStore[T]{
			db:       params.DB,
			table:    table,
			keyIndex: index,
		},
	}
	RegisterReflector(
		params.JobGroup,
		params.DB,
		KubernetesConfig[T]{
			BufferSize:     1000,
			BufferWaitTime: 50 * time.Millisecond,
			ListerWatcher:  lw,
			Table:          table,
		})

	return table, index, &statedbResource[T]{
		store: store,
		index: index,
		table: table,
		db:    params.DB,
	}
}

type statedbResource[T runtime.Object] struct {
	stream.Observable[Event[T]]
	store Store[T]
	index statedb.Index[T, Key]
	table statedb.Table[T]
	db    *statedb.DB
}

// Events implements Resource.
func (s *statedbResource[T]) Events(ctx context.Context, opts ...EventsOpt) <-chan Event[T] {
	return stream.ToChannel(ctx, s)
}

func (s *statedbResource[T]) Observe(ctx context.Context, next func(Event[T]), complete func(error)) {
	// Start observing the table.
	go func() {
		txn := s.db.WriteTxn(s.table)
		iter, err := s.table.Changes(txn)
		txn.Commit()
		if err != nil {
			complete(err)
			return
		}
		defer iter.Close()
		defer complete(nil)

		initialized := false

		for {
			for change, _, ok := iter.Next(); ok; change, _, ok = iter.Next() {
				key, err := cache.ObjectToName(change.Object)
				if err != nil {
					panic(err)
				}
				kind := Upsert
				if change.Deleted {
					kind = Delete
				}
				ev := Event[T]{
					Kind:   kind,
					Key:    key,
					Object: change.Object,
					Done: func(err error) {
						if err != nil {
							panic("statedbResource[T] does not implement workqueue")
						}
					},
				}
				next(ev)
			}

			txn := s.db.ReadTxn()
			watch := iter.Watch(txn)
			if !initialized {
				if s.table.Initialized(txn) {
					initialized = true
					next(Event[T]{
						Kind: Sync,
						Done: func(err error) {},
					})
				}
			}

			select {
			case <-ctx.Done():
				return
			case <-watch:
			}
		}
	}()
}

// Store implements Resource.
func (s *statedbResource[T]) Store(ctx context.Context) (Store[T], error) {
	for {
		txn := s.db.ReadTxn()
		if s.table.Initialized(txn) {
			return s.store, nil
		}

		// Not yet initialized. Watch for any change and then check again.
		_, watch := s.table.All(txn)

		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-watch:
		}
	}
}

// Table implements Resource.
func (s *statedbResource[T]) Table() (statedb.Index[T, cache.ObjectName], statedb.Table[T]) {
	return s.index, s.table
}

var _ Resource[*runtime.Unknown] = &statedbResource[*runtime.Unknown]{}
