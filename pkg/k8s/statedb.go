// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package k8s

import (
	"context"
	"fmt"
	"iter"
	"log/slog"
	"slices"
	"sync"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"
	"github.com/cilium/stream"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/client-go/tools/cache"

	"github.com/cilium/cilium/pkg/container"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/k8s/synced"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/promise"
	"github.com/cilium/cilium/pkg/time"
)

// RegisterReflector registers a Kubernetes to StateDB table reflector.
//
// Intended to be used with [cell.Invoke] and the module's job group.
// See [ExampleRegisterReflector] for example usage.
func RegisterReflector[Obj any](jobGroup job.Group, db *statedb.DB, cfg ReflectorConfig[Obj]) error {
	cfg = cfg.withDefaults()
	if err := cfg.validate(); err != nil {
		return err
	}

	// Register initializer that marks when the table has been initially populated,
	// e.g. the initial "List" has concluded.
	targetTable := cfg.Table
	r := &k8sReflector[Obj]{
		ReflectorConfig: cfg.withDefaults(),
		db:              db,
		table:           targetTable,
	}
	wtxn := db.WriteTxn(targetTable)
	r.initDone = targetTable.RegisterInitializer(wtxn, r.ReflectorConfig.Name)
	wtxn.Commit()

	jobGroup.Add(job.OneShot(
		r.ReflectorConfig.JobName(),
		r.run))

	return nil
}

// OnDemandTable provides an "on-demand" table of Kubernetes-derived objects.
// The table is not populated until it is first acquired.
// If the table should be cleared (to avoid holding onto the objects) when last reference
// is released, set [ReflectorConfig.ClearTableOnStop].
//
// Intended to be used with [cell.Provide].
// See [ExampleOnDemand] for example usage.
func OnDemandTable[Obj any](jobs job.Registry, health cell.Health, log *slog.Logger, db *statedb.DB, cfg ReflectorConfig[Obj]) (hive.OnDemand[statedb.Table[Obj]], error) {
	lc := &cell.DefaultLifecycle{}
	// Job group for the reflector that will be started when the table
	// is acquired.
	jg := jobs.NewGroup(
		health,
		lc,
		job.WithLogger(log),
	)

	err := RegisterReflector(jg, db, cfg)
	if err != nil {
		return nil, err
	}

	return hive.NewOnDemand(
		log,
		cfg.Table.ToTable(),
		lc,
	), nil
}

type ReflectorConfig[Obj any] struct {
	// Mandatory name of the reflector. This is used as the table initializer name and as
	// the reflector job name.
	Name string

	// Mandatory table to reflect the objects to.
	Table statedb.RWTable[Obj]

	// Mandatory ListerWatcher to use to retrieve the objects.
	//
	// Use [utils.ListerWatcherFromTyped] to create one from the Clientset, e.g.
	//
	//   var cs client.Clientset
	//   utils.ListerWatcherFromTyped(cs.CoreV1().Nodes())
	//
	ListerWatcher cache.ListerWatcher

	// Optional maximum number of objects to commit in one transaction. Uses default if left zero.
	// This does not apply to the initial listing which is committed in one go.
	BufferSize int

	// Optional amount of time to wait for the buffer to fill. Uses default if left zero.
	BufferWaitTime time.Duration

	// Optional function to transform the objects given by the ListerWatcher. This can
	// be used to convert into an internal model on the fly to save space and add additional
	// fields or to for example implement TableRow/TableHeader for the "db/show" command.
	//
	// The object given to the transform function can be modified without copying.
	Transform TransformFunc[Obj]

	// Optional function to transform the object to a set of objects to insert or delete.
	// If set, [Transform] must be nil.
	//
	// The object given to the transform function can be modified without copying.
	TransformMany TransformManyFunc[Obj]

	// Optional function to query all objects. Used when replacing the objects on resync.
	// This can be used to "namespace" the objects managed by this reflector, e.g. on
	// source.Source etc.
	//
	// This function becomes mandatory when working with multiple sources to avoid deleting
	// all objects when the underlying `cache.Reflector` needs to `Replace()` all items during
	// a resync.
	QueryAll QueryAllFunc[Obj]

	// Optional function to merge the new object with an existing object in the target
	// table.
	Merge MergeFunc[Obj]

	// Optional promise for waiting for the CRD referenced by the [ListerWatcher] to
	// be registered.
	CRDSync promise.Promise[synced.CRDSync]

	// ClearTableOnStop if true will cause all inserted objects to be deleted (using QueryAll)
	// when the reflector is stopped.
	ClearTableOnStop bool
}

// JobName returns the name of the background reflector job.
func (cfg ReflectorConfig[Obj]) JobName() string {
	return fmt.Sprintf("k8s-reflector-%s-%s", cfg.Table.Name(), cfg.Name)
}

// TransformFunc is an optional function to give to the reflector
// to transform the object returned by the ListerWatcher to the desired
// target object. If the function returns false the object is silently
// skipped.
//
// The object given to the transform function can be modified without copying.
type TransformFunc[Obj any] func(statedb.ReadTxn, any) (obj Obj, ok bool)

// TransformManyFunc is an optional function to give to the reflector
// to transform the object returned by the ListerWatcher to the desired set of
// target objects to insert or delete.
//
// The object given to the transform function can be modified without copying.
type TransformManyFunc[Obj any] func(txn statedb.ReadTxn, deleted bool, obj any) (toInsert, toDelete iter.Seq[Obj])

// QueryAllFunc is an optional function to give to the Kubernetes reflector
// to query all objects in the table that are managed by the reflector.
// It is used to delete all objects when the underlying cache.Reflector needs
// to Replace() all items for a resync.
type QueryAllFunc[Obj any] func(statedb.ReadTxn, statedb.Table[Obj]) iter.Seq2[Obj, statedb.Revision]

// MergeFunc is an optional function to merge the new object with an existing
// object in th target table. Only invoked if an old object exists.
type MergeFunc[Obj any] func(old Obj, new Obj) Obj

const (
	// DefaultBufferSize is the maximum number of objects to commit to the table in one write transaction.
	// This limit does not apply to the initial listing (Replace()) which commits all listed objects in one
	// transaction.
	DefaultBufferSize = 10000

	// DefaultBufferWaitTime is the amount of time to wait to fill the buffer before committing objects.
	// 10000 * 50ms => 200k objects per second throughput limit.
	DefaultBufferWaitTime = 50 * time.Millisecond
)

// withDefaults fills in unset fields with default values.
func (cfg ReflectorConfig[Obj]) withDefaults() ReflectorConfig[Obj] {
	if cfg.BufferSize == 0 {
		cfg.BufferSize = DefaultBufferSize
	}
	if cfg.BufferWaitTime == 0 {
		cfg.BufferWaitTime = DefaultBufferWaitTime
	}
	return cfg
}

func (cfg ReflectorConfig[Obj]) validate() error {
	if cfg.Name == "" {
		return fmt.Errorf("%T.Name cannot be empty", cfg)
	}
	if cfg.Table == nil {
		return fmt.Errorf("%T.Table cannot be nil", cfg)
	}
	if cfg.ListerWatcher == nil {
		return fmt.Errorf("%T.ListerWatcher cannot be nil", cfg)
	}
	if cfg.BufferSize <= 0 {
		return fmt.Errorf("%T.BufferSize (%d) must be larger than zero", cfg, cfg.BufferSize)
	}
	if cfg.BufferWaitTime <= 0 {
		return fmt.Errorf("%T.BufferWaitTime (%d) must be larger than zero", cfg, cfg.BufferWaitTime)
	}
	if cfg.Transform != nil && cfg.TransformMany != nil {
		return fmt.Errorf("Both %T.Transform and .TransformMany cannot be set", cfg)
	}
	return nil
}

type k8sReflector[Obj any] struct {
	ReflectorConfig[Obj]

	log      *slog.Logger
	initDone func(statedb.WriteTxn)
	db       *statedb.DB
	table    statedb.RWTable[Obj]
}

func (r *k8sReflector[Obj]) run(ctx context.Context, health cell.Health) error {
	if r.CRDSync != nil {
		// Wait for the CRD to be registered.
		health.OK("Waiting for CRD registration")
		if _, err := r.CRDSync.Await(ctx); err != nil {
			return err
		}
	}

	type entry struct {
		deleted   bool
		name      string
		namespace string
		obj       any
	}
	type buffer struct {
		replaceItems []any
		entries      *container.InsertOrderedMap[string, entry]
	}
	var bufferPool = sync.Pool{
		New: func() any {
			return &buffer{
				entries: container.NewInsertOrderedMap[string, entry](),
			}
		},
	}
	bufferSize := r.BufferSize
	waitTime := r.BufferWaitTime
	table := r.table

	transformMany := r.TransformMany
	if transformMany == nil {
		// Reusing the same buffer for efficiency.
		buf := make([]Obj, 1)
		if r.Transform != nil {
			// Implement TransformMany with Transform.
			transformMany = TransformManyFunc[Obj](func(txn statedb.ReadTxn, deleted bool, obj any) (toInsert, toDelete iter.Seq[Obj]) {
				var ok bool
				if buf[0], ok = r.Transform(txn, obj); ok {
					if deleted {
						return nil, slices.Values(buf)
					}
					return slices.Values(buf), nil
				}
				return nil, nil
			})
		} else {
			// No provided transform function, use the identity function instead.
			transformMany = TransformManyFunc[Obj](func(txn statedb.ReadTxn, deleted bool, obj any) (toInsert, toDelete iter.Seq[Obj]) {
				buf[0] = obj.(Obj)
				if deleted {
					return nil, slices.Values(buf)
				}
				return slices.Values(buf), nil
			})
		}
	}

	queryAll := r.QueryAll
	if queryAll == nil {
		// No query function provided, use All()
		queryAll = QueryAllFunc[Obj](func(txn statedb.ReadTxn, tbl statedb.Table[Obj]) iter.Seq2[Obj, statedb.Revision] {
			return tbl.All(txn)
		})
	}

	merge := r.Merge
	if merge == nil {
		merge = func(old, new Obj) Obj {
			return new
		}
	}

	// Construct a stream of K8s objects, buffered into chunks every [waitTime] period
	// and then committed.
	// This reduces the number of write transactions required and thus the number of times
	// readers get woken up, which results in much better overall throughput.
	src := stream.Buffer(
		ListerWatcherToObservable(r.ListerWatcher),
		bufferSize,
		waitTime,

		// Buffer the events into a map, coalescing them by key.
		func(buf *buffer, ev CacheStoreEvent) *buffer {
			if buf == nil {
				buf = bufferPool.Get().(*buffer)
			}
			if ev.Kind == CacheStoreEventReplace {
				buf.replaceItems = ev.Obj.([]any)
				buf.entries.Clear()
				return buf
			}

			var entry entry
			entry.obj = ev.Obj
			entry.deleted = ev.Kind == CacheStoreEventDelete

			meta, err := meta.Accessor(ev.Obj)
			if err != nil {
				panic(fmt.Sprintf("%T internal error: meta.Accessor failed: %s", r, err))
			}
			entry.name = meta.GetName()
			entry.namespace = meta.GetNamespace()
			var key string
			if entry.namespace != "" {
				key = entry.namespace + "/" + entry.name
			} else {
				key = entry.name
			}
			buf.entries.Insert(key, entry)
			return buf
		},
	)

	commitBuffer := func(buf *buffer) {
		numUpserted, numDeleted := 0, 0

		txn := r.db.WriteTxn(table)
		if buf.replaceItems != nil {
			indexer := table.PrimaryIndexer()
			inserted := sets.New[string]()

			for _, item := range buf.replaceItems {
				toInsert, _ := transformMany(txn, false, item)
				// Ignoring the 'toDelete' since we're going to use queryAll below to
				// delete everything we didn't insert here.
				if toInsert != nil {
					for obj := range toInsert {
						if _, _, err := table.Insert(txn, obj); err != nil {
							r.log.Error("BUG: Insert failed", logfields.Error, err)
							continue
						}

						numUpserted++
						inserted.Insert(string(indexer.ObjectToKey(obj)))
					}
				}
			}

			// Delete the remaining objects that we did not insert.
			for obj := range queryAll(txn, table) {
				if !inserted.Has(string(indexer.ObjectToKey(obj))) {
					if _, _, err := table.Delete(txn, obj); err != nil {
						r.log.Error("BUG: Delete failed", logfields.Error, err)
						continue
					}
					numDeleted++
				}
			}

			// Mark the table as initialized. Internally this has a sync.Once
			// so safe to call multiple times.
			r.initDone(txn)
		}

		for entry := range buf.entries.Values() {
			toInsert, toDelete := transformMany(txn, entry.deleted, entry.obj)
			if toInsert != nil {
				for obj := range toInsert {
					if _, _, err := table.Modify(txn, obj, merge); err != nil {
						r.log.Error("BUG: Modify failed", logfields.Error, err)
					} else {
						numUpserted++
					}
				}
			}
			if toDelete != nil {
				for obj := range toDelete {
					if _, _, err := table.Delete(txn, obj); err != nil {
						r.log.Error("BUG: Delete failed", logfields.Error, err)
					} else {
						numDeleted++
					}
				}
			}
		}

		numTotal := table.NumObjects(txn)
		txn.Commit()

		buf.replaceItems = nil
		buf.entries.Clear()
		bufferPool.Put(buf)

		health.OK(fmt.Sprintf("%d upserted, %d deleted, %d total objects", numUpserted, numDeleted, numTotal))
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
	err := <-errs

	if r.ClearTableOnStop {
		txn := r.db.WriteTxn(table)
		for obj := range queryAll(txn, table) {
			table.Delete(txn, obj)
		}
		txn.Commit()
	}

	return err
}

// ListerWatcherToObservable turns a ListerWatcher into an observable using the
// client-go's Reflector.
func ListerWatcherToObservable(lw cache.ListerWatcher) stream.Observable[CacheStoreEvent] {
	return stream.FuncObservable[CacheStoreEvent](
		func(ctx context.Context, next func(CacheStoreEvent), complete func(err error)) {
			store := &cacheStoreListener{
				onAdd: func(obj any) {
					next(CacheStoreEvent{CacheStoreEventAdd, obj})
				},
				onUpdate:  func(obj any) { next(CacheStoreEvent{CacheStoreEventUpdate, obj}) },
				onDelete:  func(obj any) { next(CacheStoreEvent{CacheStoreEventDelete, obj}) },
				onReplace: func(objs []any) { next(CacheStoreEvent{CacheStoreEventReplace, objs}) },
			}
			reflector := cache.NewReflector(lw, nil, store, 0)
			go func() {
				reflector.Run(ctx.Done())
				complete(nil)
			}()
		})
}

type CacheStoreEventKind int

const (
	CacheStoreEventAdd = CacheStoreEventKind(iota)
	CacheStoreEventUpdate
	CacheStoreEventDelete
	CacheStoreEventReplace
)

type CacheStoreEvent struct {
	Kind CacheStoreEventKind
	Obj  any
}

// cacheStoreListener implements the methods used by the cache reflector and
// calls the given handlers for added, updated and deleted objects.
type cacheStoreListener struct {
	onAdd, onUpdate, onDelete func(any)
	onReplace                 func([]any)
}

func (s *cacheStoreListener) Add(obj any) error {
	s.onAdd(obj)
	return nil
}

func (s *cacheStoreListener) Update(obj any) error {
	s.onUpdate(obj)
	return nil
}

func (s *cacheStoreListener) Delete(obj any) error {
	s.onDelete(obj)
	return nil
}

func (s *cacheStoreListener) Replace(items []any, resourceVersion string) error {
	if items == nil {
		// Always emit a non-nil slice for replace.
		items = []any{}
	}
	s.onReplace(items)
	return nil
}

// These methods are never called by cache.Reflector:

func (*cacheStoreListener) Get(obj any) (item any, exists bool, err error) {
	panic("unimplemented")
}
func (*cacheStoreListener) GetByKey(key string) (item any, exists bool, err error) {
	panic("unimplemented")
}
func (*cacheStoreListener) List() []any        { panic("unimplemented") }
func (*cacheStoreListener) ListKeys() []string { panic("unimplemented") }
func (*cacheStoreListener) Resync() error      { panic("unimplemented") }

var _ cache.Store = &cacheStoreListener{}
