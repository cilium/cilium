// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package k8s_test

import (
	"context"
	"fmt"
	"iter"
	"slices"
	"sync/atomic"
	"testing"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/cilium/statedb"
	"github.com/cilium/statedb/index"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/k8s"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/synced"
	"github.com/cilium/cilium/pkg/k8s/testutils"
	"github.com/cilium/cilium/pkg/k8s/utils"
	"github.com/cilium/cilium/pkg/promise"
	"github.com/cilium/cilium/pkg/time"
)

var nodeNameIndex = statedb.Index[*corev1.Node, string]{
	Name: "name",
	FromObject: func(obj *corev1.Node) index.KeySet {
		return index.NewKeySet(index.String(obj.Name))
	},
	FromKey: index.String,
	Unique:  true,
}

func newNodeTable(db *statedb.DB) (statedb.RWTable[*corev1.Node], error) {
	tbl, err := statedb.NewTable(
		"nodes",
		nodeNameIndex,
	)
	if err != nil {
		return nil, err
	}
	return tbl, db.RegisterTable(tbl)
}

func ExampleRegisterReflector() {
	module := cell.Module(
		"example-reflector",
		"Reflector example",

		cell.ProvidePrivate(
			// Construct the table we're reflecting to.
			newNodeTable,

			// ReflectorConfig defines the ListerWatcher to use the fetch the objects
			// and how to write them to the table.
			func(client k8sClient.Clientset, tbl statedb.RWTable[*corev1.Node]) k8s.ReflectorConfig[*corev1.Node] {
				return k8s.ReflectorConfig[*corev1.Node]{
					Name:          "nodes",
					Table:         tbl,
					ListerWatcher: utils.ListerWatcherFromTyped(client.CoreV1().Nodes()),
				}
			},
		),

		// Provide Table[*Node] for read-access to all modules in the application.
		cell.Provide(statedb.RWTable[*corev1.Node].ToTable),

		// Register the reflector to this module's job group.
		cell.Invoke(k8s.RegisterReflector[*corev1.Node]),
	)

	hive.New(module)
}

func ExampleOnDemand() {
	module := cell.Module(
		"example-on-demand",
		"OnDemand example",

		cell.ProvidePrivate(
			// Construct the table we're reflecting to.
			newNodeTable,

			// ReflectorConfig defines the ListerWatcher to use the fetch the objects
			// and how to write them to the table.
			func(client k8sClient.Clientset, tbl statedb.RWTable[*corev1.Node]) k8s.ReflectorConfig[*corev1.Node] {
				return k8s.ReflectorConfig[*corev1.Node]{
					Name:          "nodes",
					Table:         tbl,
					ListerWatcher: utils.ListerWatcherFromTyped(client.CoreV1().Nodes()),
				}
			},
		),

		// Provide OnDemand[Table[*Node]] to the application.
		cell.Provide(k8s.OnDemandTable[*corev1.Node]),
	)

	hive.New(module)
}

type testObject struct {
	metav1.PartialObjectMetadata
	Status    string
	Merge     string
	Transform string
}

func (t *testObject) DeepCopy() *testObject {
	t2 := *t
	return &t2
}

var (
	testNameIndex = statedb.Index[*testObject, string]{
		Name: "name",
		FromObject: func(obj *testObject) index.KeySet {
			return index.NewKeySet(index.String(obj.Name))
		},
		FromKey: index.String,
		Unique:  true,
	}
)

func newTestTable(db *statedb.DB) (statedb.RWTable[*testObject], error) {
	tbl, err := statedb.NewTable(
		"test",
		testNameIndex,
	)
	if err != nil {
		return nil, err
	}
	return tbl, db.RegisterTable(tbl)
}

type reflectorTestParams struct {
	doTransform     bool
	doTransformMany bool
	doQueryAll      bool
	doMerge         bool
	doCRDSync       bool
}

func TestStateDBReflector(t *testing.T) {
	t.Run("default", func(t *testing.T) {
		testStateDBReflector(t, reflectorTestParams{})
	})

	t.Run("crdsync", func(t *testing.T) {
		testStateDBReflector(t, reflectorTestParams{doCRDSync: true})
	})

	t.Run("Transform", func(t *testing.T) {
		testStateDBReflector(t, reflectorTestParams{
			doTransform: true,
		})
	})
	t.Run("TransformMany", func(t *testing.T) {
		testStateDBReflector(t, reflectorTestParams{
			doTransformMany: true,
		})
	})
	t.Run("TransformMany-QueryAll", func(t *testing.T) {
		testStateDBReflector(t, reflectorTestParams{
			doTransformMany: true,
			doQueryAll:      true,
		})
	})
	t.Run("TransformMany-Merge", func(t *testing.T) {
		testStateDBReflector(t, reflectorTestParams{
			doTransformMany: true,
			doMerge:         true,
		})
	})
}

func testStateDBReflector(t *testing.T, p reflectorTestParams) {
	var (
		obj1Name = "obj1"
		obj2Name = "obj2"
		obj      = &testObject{
			PartialObjectMetadata: metav1.PartialObjectMetadata{
				ObjectMeta: metav1.ObjectMeta{
					Name:            obj1Name,
					ResourceVersion: "0",
				},
			},
			Status: "init",
			Merge:  "X",
		}

		db                                           *statedb.DB
		table                                        statedb.Table[*testObject]
		transformCalled, queryAllCalled, mergeCalled atomic.Bool
	)

	lw := testutils.NewFakeListerWatcher(
		obj.DeepCopy(),
	)

	var testTimeout = 10 * time.Second
	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	var transformFunc k8s.TransformFunc[*testObject]
	if p.doTransform {
		transformFunc = func(_ statedb.ReadTxn, a any) (obj *testObject, ok bool) {
			transformCalled.Store(true)
			obj = a.(*testObject).DeepCopy()
			obj.Transform = "transform"
			return obj, true
		}
	}
	var transformManyFunc k8s.TransformManyFunc[*testObject]
	if p.doTransformMany {
		transformManyFunc = func(_ statedb.ReadTxn, deleted bool, a any) (toInsert, toDelete iter.Seq[*testObject]) {
			transformCalled.Store(true)
			obj := a.(*testObject).DeepCopy()
			obj.Transform = "transform-many"
			if deleted {
				return nil, slices.Values([]*testObject{obj})
			}
			return slices.Values([]*testObject{obj}), nil
		}
	}

	var queryAllFunc k8s.QueryAllFunc[*testObject]
	if p.doQueryAll {
		queryAllFunc = func(txn statedb.ReadTxn, tbl statedb.Table[*testObject]) iter.Seq2[*testObject, statedb.Revision] {
			// This method is called on the initial synchronization (e.g. Replace()) and whenever
			// connection is lost to api-server and resynchronization is needed.
			queryAllCalled.Store(true)
			return tbl.All(txn)
		}
	}

	var mergeFunc k8s.MergeFunc[*testObject]
	if p.doMerge {
		mergeFunc = func(old, new *testObject) *testObject {
			mergeCalled.Store(true)
			new.Merge = old.Merge + new.Merge
			return new
		}
	}

	var crdSyncPromise promise.Promise[synced.CRDSync]
	var crdSyncResolver promise.Resolver[synced.CRDSync]
	if p.doCRDSync {
		crdSyncResolver, crdSyncPromise = promise.New[synced.CRDSync]()
	}

	hive := hive.New(
		cell.Module("test", "test",
			cell.ProvidePrivate(
				func(tbl statedb.RWTable[*testObject]) k8s.ReflectorConfig[*testObject] {
					return k8s.ReflectorConfig[*testObject]{
						Name:           "test",
						Table:          tbl,
						BufferSize:     10,
						BufferWaitTime: 10 * time.Millisecond,
						ListerWatcher:  lw,
						Transform:      transformFunc,
						TransformMany:  transformManyFunc,
						QueryAll:       queryAllFunc,
						Merge:          mergeFunc,
						CRDSync:        crdSyncPromise,
					}
				},
				newTestTable,
			),
			cell.Invoke(
				k8s.RegisterReflector[*testObject],
				func(db_ *statedb.DB, tbl statedb.RWTable[*testObject]) {
					// Insert a dummy node into the table to verify that the initial synchronization
					// cleans things up.
					// BTW, if you don't want everything cleaned up you can specify the QueryAll
					// function to "namespace" what the reflector is managing.
					wtxn := db_.WriteTxn(tbl)
					var garbageNode testObject
					garbageNode.Name = "garbage"
					tbl.Insert(wtxn, &garbageNode)
					wtxn.Commit()

					db = db_
					table = tbl
				}),
		),
	)

	tlog := hivetest.Logger(t)
	if err := hive.Start(tlog, ctx); err != nil {
		t.Fatalf("hive.Start failed: %s", err)
	}

	if p.doCRDSync {
		// The reflector should be waiting for the CRDSync promise before marking
		// the table initialized.
		initialized, _ := table.Initialized(db.ReadTxn())
		require.False(t, initialized, "table unexpectedly initialized with unresolved CRDSync")
		crdSyncResolver.Resolve(synced.CRDSync{})
	}

	// Wait until the table has been initialized.
	_, initWatch := table.Initialized(db.ReadTxn())
	<-initWatch

	// After initialization we should see the node that was created
	// before starting.
	iter, watch := table.AllWatch(db.ReadTxn())
	objs := statedb.Collect(iter)
	require.Len(t, objs, 1)
	require.Equal(t, obj1Name, objs[0].Name)

	if p.doTransform {
		require.Equal(t, "transform", objs[0].Transform)
	}
	if p.doTransformMany {
		require.Equal(t, "transform-many", objs[0].Transform)
	}

	// Update the object and check that it updated.
	obj.Status = "update1"
	obj.Merge = "Y"
	lw.Upsert(obj.DeepCopy())

	<-watch
	iter, watch = table.AllWatch(db.ReadTxn())
	objs = statedb.Collect(iter)
	require.Len(t, objs, 1)
	require.Equal(t, "update1", objs[0].Status)
	if p.doMerge {
		// Merge is set, "Merge" fields are concat'd
		require.Equal(t, "XY", objs[0].Merge)
	} else {
		// Merge is not set, only the new "Merge" field is kept.
		require.Equal(t, "Y", objs[0].Merge)
	}

	// Create another node after initialization.
	node2 := obj.DeepCopy()
	node2.ObjectMeta.Name = obj2Name
	lw.Upsert(node2.DeepCopy())

	// Wait until updated.
	<-watch
	iter, watch = table.AllWatch(db.ReadTxn())
	objs = statedb.Collect(iter)
	require.Len(t, objs, 2)
	require.Equal(t, obj1Name, objs[0].Name)
	require.Equal(t, obj2Name, objs[1].Name)

	// Update the nodes back to back. The ordering must be retained even when
	// the changes land in the same buffer.
	for i := range 10 {
		fst := i%2 == 0
		if fst {
			lw.Upsert(obj.DeepCopy())
			lw.Upsert(node2.DeepCopy())
		} else {
			lw.Upsert(node2.DeepCopy())
			lw.Upsert(obj.DeepCopy())
		}
		<-watch
		iter, watch = table.LowerBoundWatch(db.ReadTxn(), statedb.ByRevision[*testObject](0))
		objs = statedb.Collect(iter)
		require.Len(t, objs, 2)
		if fst {
			require.Equal(t, obj1Name, objs[0].Name)
			require.Equal(t, obj2Name, objs[1].Name)
		} else {
			require.Equal(t, obj2Name, objs[0].Name)
			require.Equal(t, obj1Name, objs[1].Name)
		}
	}

	// Finally delete the nodes
	lw.Delete(obj)

	<-watch
	iter, watch = table.AllWatch(db.ReadTxn())
	objs = statedb.Collect(iter)
	require.Len(t, objs, 1)
	require.Equal(t, obj2Name, objs[0].Name)

	lw.Delete(node2)

	<-watch
	iter, _ = table.AllWatch(db.ReadTxn())
	objs = statedb.Collect(iter)
	require.Empty(t, objs)

	// Finally check that the hive stops correctly. Note that we're not doing this in a
	// defer to avoid potentially deadlocking on the Fatal calls.
	if err := hive.Stop(tlog, context.TODO()); err != nil {
		t.Fatalf("hive.Stop failed: %s", err)
	}

	if p.doTransform || p.doTransformMany {
		assert.True(t, transformCalled.Load(), "provided transform func not used")
	}
	if p.doQueryAll {
		assert.True(t, queryAllCalled.Load(), "provided query all func not used")
	}
}

func TestStateDBReflector_jobName(t *testing.T) {
	tbl, _ := statedb.NewTable(
		"node",
		testNameIndex,
	)
	cfg := k8s.ReflectorConfig[*testObject]{
		Name:  "test",
		Table: tbl,
	}

	assert.Equal(
		t,
		"k8s-reflector-node-test",
		cfg.JobName(),
	)
}

func TestOnDemandTable(t *testing.T) {
	obj := &testObject{
		PartialObjectMetadata: metav1.PartialObjectMetadata{
			ObjectMeta: metav1.ObjectMeta{
				Name: "test",
			},
		},
	}
	lw := testutils.NewFakeListerWatcher(obj.DeepCopy())

	var (
		db     *statedb.DB
		wtbl   statedb.RWTable[*testObject]
		otable hive.OnDemand[statedb.Table[*testObject]]
	)

	hive := hive.New(
		cell.Module("test", "test",
			cell.ProvidePrivate(
				func(tbl statedb.RWTable[*testObject]) k8s.ReflectorConfig[*testObject] {
					wtbl = tbl
					return k8s.ReflectorConfig[*testObject]{
						Name:             "test",
						Table:            tbl,
						BufferSize:       10,
						BufferWaitTime:   time.Millisecond,
						ListerWatcher:    lw,
						ClearTableOnStop: true,
					}
				},
				newTestTable,
				k8s.OnDemandTable[*testObject],
			),
			cell.Invoke(
				func(db_ *statedb.DB, tbl hive.OnDemand[statedb.Table[*testObject]]) {
					db = db_
					otable = tbl
				},
			),
		),
	)

	tlog := hivetest.Logger(t)
	ctx := context.TODO()
	require.NoError(t, hive.Start(tlog, ctx), "Start")

	require.NotNil(t, otable)

	// Table is not populated before it is acquired.
	assert.Zero(t, wtbl.NumObjects(db.ReadTxn()), "expected empty table")

	// Acquiring the table starts the reflector.
	table, err := otable.Acquire(ctx)
	assert.NoError(t, err, "Acquire")
	require.NotNil(t, table)

	// The initial object is inserted into the table now that we acquired
	// it.
	assert.Eventually(
		t, func() bool { return table.NumObjects(db.ReadTxn()) == 1 },
		5*time.Second, 10*time.Millisecond,
		"Table not populated after Acquire",
	)

	obj2 := obj.DeepCopy()
	obj2.Name = "test2"
	lw.Upsert(obj2)

	// Test with another acquired table.
	table2, err := otable.Acquire(ctx)
	assert.NoError(t, err, "Acquire")
	require.Same(t, table, table2)

	assert.Eventually(
		t, func() bool { return table2.NumObjects(db.ReadTxn()) == 2 },
		5*time.Second, 10*time.Millisecond,
		"Second object not added",
	)

	// Release the second one. This does not yet stop the reflection.
	err = otable.Release(table2)
	assert.NoError(t, err, "Release")

	obj3 := obj.DeepCopy()
	obj3.Name = "test3"
	lw.Upsert(obj3)

	assert.Eventually(
		t, func() bool { return table2.NumObjects(db.ReadTxn()) == 3 },
		5*time.Second, 10*time.Millisecond,
		"Third object not added after release of table",
	)

	// Release the last one. This stops the reflection and clears the table.
	err = otable.Release(table)
	assert.NoError(t, err, "Release")

	assert.Eventually(
		t, func() bool { return wtbl.NumObjects(db.ReadTxn()) == 0 },
		5*time.Second, 10*time.Millisecond,
		"Table not cleared after all have been released",
	)

	assert.NoError(t, hive.Stop(tlog, ctx), "Stop")
}

func BenchmarkStateDBReflector(b *testing.B) {
	var (
		db    *statedb.DB
		table statedb.Table[*testObject]
	)

	lw := testutils.NewFakeListerWatcher()

	hive := hive.New(
		cell.Module("test", "test",
			cell.ProvidePrivate(
				func(tbl statedb.RWTable[*testObject]) k8s.ReflectorConfig[*testObject] {
					return k8s.ReflectorConfig[*testObject]{
						Name:           "test",
						Table:          tbl,
						ListerWatcher:  lw,
						BufferSize:     1024,
						BufferWaitTime: time.Millisecond,
					}
				},
				newTestTable,
			),
			cell.Invoke(
				k8s.RegisterReflector[*testObject],
				func(db_ *statedb.DB, tbl statedb.RWTable[*testObject]) {
					db = db_
					table = tbl
				}),
		),
	)

	tlog := hivetest.Logger(b)
	if err := hive.Start(tlog, context.TODO()); err != nil {
		b.Fatalf("hive.Start failed: %s", err)
	}

	// Wait until the table has been initialized.
	_, initWatch := table.Initialized(db.ReadTxn())
	<-initWatch

	const numObjects = 10000

	objs := make([]*testObject, numObjects)
	for i := range objs {
		obj := &testObject{}
		obj.Name = fmt.Sprintf("obj-%d", i)
		objs[i] = obj
	}

	// Do n rounds of upserting and deleting [numObjects] to benchmark the throughput
	for b.Loop() {
		for _, obj := range objs {
			lw.Upsert(obj.DeepCopy())
		}
		for {
			if table.NumObjects(db.ReadTxn()) == numObjects {
				break
			}
			time.Sleep(time.Millisecond)
		}
		for _, obj := range objs {
			lw.Delete(obj.DeepCopy())
		}
		for {
			if table.NumObjects(db.ReadTxn()) == 0 {
				break
			}
			time.Sleep(time.Millisecond)
		}
	}

	b.StopTimer()

	// Slightly wonky metric as we're doing both Upsert and Delete, so it's averaging
	// over the cost of these.
	b.ReportMetric(float64(b.N*numObjects*2)/b.Elapsed().Seconds(), "objects/sec")

	// Finally check that the hive stops correctly. Note that we're not doing this in a
	// defer to avoid potentially deadlocking on the Fatal calls.
	if err := hive.Stop(tlog, context.TODO()); err != nil {
		b.Fatalf("hive.Stop failed: %s", err)
	}
}
