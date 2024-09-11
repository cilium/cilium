// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package k8s_test

import (
	"context"
	"fmt"
	"iter"
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
	"github.com/cilium/cilium/pkg/k8s/testutils"
	"github.com/cilium/cilium/pkg/k8s/utils"
	"github.com/cilium/cilium/pkg/time"
)

func ExampleRegisterReflector() {
	nodeNameIndex := statedb.Index[*corev1.Node, string]{
		Name: "name",
		FromObject: func(obj *corev1.Node) index.KeySet {
			return index.NewKeySet(index.String(obj.Name))
		},
		FromKey: index.String,
		Unique:  true,
	}

	module := cell.Module(
		"example-reflector",
		"Reflector example",

		cell.ProvidePrivate(
			// Construct the table we're reflecting to.
			func(db *statedb.DB) (statedb.RWTable[*corev1.Node], error) {
				tbl, err := statedb.NewTable(
					"nodes",
					nodeNameIndex,
				)
				if err != nil {
					return nil, err
				}
				return tbl, db.RegisterTable(tbl)
			},

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
}

func TestStateDBReflector(t *testing.T) {
	t.Run("default", func(t *testing.T) {
		testStateDBReflector(t, reflectorTestParams{})
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
		transformFunc = func(a any) (obj *testObject, ok bool) {
			transformCalled.Store(true)
			obj = a.(*testObject).DeepCopy()
			obj.Transform = "transform"
			return obj, true
		}
	}
	var transformManyFunc k8s.TransformManyFunc[*testObject]
	if p.doTransformMany {
		transformManyFunc = func(a any) (objs []*testObject) {
			transformCalled.Store(true)
			obj := a.(*testObject).DeepCopy()
			obj.Transform = "transform-many"
			return []*testObject{obj}
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

	hive := hive.New(
		cell.Module("test", "test",
			cell.ProvidePrivate(
				func(tbl statedb.RWTable[*testObject]) k8s.ReflectorConfig[*testObject] {
					return k8s.ReflectorConfig[*testObject]{
						Name:           "test",
						Table:          tbl,
						BufferSize:     10,
						BufferWaitTime: time.Millisecond,
						ListerWatcher:  lw,
						Transform:      transformFunc,
						TransformMany:  transformManyFunc,
						QueryAll:       queryAllFunc,
						Merge:          mergeFunc,
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

	// Finally delete the nodes
	lw.Delete(obj)

	<-watch
	iter, watch = table.AllWatch(db.ReadTxn())
	objs = statedb.Collect(iter)
	require.Len(t, objs, 1)
	require.EqualValues(t, obj2Name, objs[0].Name)

	lw.Delete(node2)

	<-watch
	iter, _ = table.AllWatch(db.ReadTxn())
	objs = statedb.Collect(iter)
	require.Len(t, objs, 0)

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

	b.ResetTimer()

	// Do n rounds of upserting and deleting [numObjects] to benchmark the throughput
	for n := 0; n < b.N; n++ {
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
