// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package k8s_test

import (
	"context"
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
	"github.com/cilium/cilium/pkg/k8s/utils"
	"github.com/cilium/cilium/pkg/time"
)

func ExampleRegisterReflector() {
	var module = cell.Module(
		"example-reflector",
		"Reflector example",

		cell.ProvidePrivate(
			// The table the reflector writes to (RWTable[*Node]).
			newTestNodeTable,

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

var (
	testNodeNameIndex = statedb.Index[*corev1.Node, string]{
		Name: "name",
		FromObject: func(obj *corev1.Node) index.KeySet {
			return index.NewKeySet(index.String(obj.Name))
		},
		FromKey: index.String,
		Unique:  true,
	}
)

func newTestNodeTable(db *statedb.DB) (statedb.RWTable[*corev1.Node], error) {
	tbl, err := statedb.NewTable(
		"test-nodes",
		testNodeNameIndex,
	)
	if err != nil {
		return nil, err
	}
	return tbl, db.RegisterTable(tbl)
}

func TestStateDBReflector(t *testing.T) {
	testStateDBReflector(t, false, false)
}

func TestStateDBReflector_Transform(t *testing.T) {
	testStateDBReflector(t, true, false)
}

func TestStateDBReflector_QueryAll(t *testing.T) {
	testStateDBReflector(t, false, true)
}

func TestStateDBReflector_TransformQueryAll(t *testing.T) {
	testStateDBReflector(t, true, true)
}

func testStateDBReflector(t *testing.T, doTransform, doQueryAll bool) {
	var (
		node1Name = "node1"
		node2Name = "node2"
		node      = &corev1.Node{
			ObjectMeta: metav1.ObjectMeta{
				Name:            node1Name,
				ResourceVersion: "0",
			},
			Status: corev1.NodeStatus{
				Phase: "init",
			},
		}
		fakeClient, cs = k8sClient.NewFakeClientset()

		db                              *statedb.DB
		nodeTable                       statedb.Table[*corev1.Node]
		transformCalled, queryAllCalled atomic.Bool
	)

	// Create the initial version of the node. Do this before anything
	// starts watching the resources to avoid a race.
	fakeClient.KubernetesFakeClientset.Tracker().Create(
		corev1.SchemeGroupVersion.WithResource("nodes"),
		node.DeepCopy(), "")

	var testTimeout = 10 * time.Second
	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	var transformFunc k8s.TransformFunc[*corev1.Node]
	if doTransform {
		transformFunc = func(a any) (obj *corev1.Node, ok bool) {
			transformCalled.Store(true)
			obj = a.(*corev1.Node).DeepCopy()
			obj.ObjectMeta.GenerateName = "transformed"
			return obj, true
		}
	}

	var queryAllFunc k8s.QueryAllFunc[*corev1.Node]
	if doQueryAll {
		queryAllFunc = func(txn statedb.ReadTxn, tbl statedb.Table[*corev1.Node]) statedb.Iterator[*corev1.Node] {
			// This method is called on the initial synchronization (e.g. Replace()) and whenever
			// connection is lost to api-server and resynchronization is needed.
			queryAllCalled.Store(true)
			return tbl.All(txn)
		}
	}

	hive := hive.New(
		cell.Provide(func() k8sClient.Clientset { return cs }),
		cell.Module("test", "test",
			cell.ProvidePrivate(
				func(client k8sClient.Clientset, tbl statedb.RWTable[*corev1.Node]) k8s.ReflectorConfig[*corev1.Node] {
					return k8s.ReflectorConfig[*corev1.Node]{
						Name:           "nodes",
						Table:          tbl,
						BufferSize:     10,
						BufferWaitTime: time.Millisecond,
						ListerWatcher:  utils.ListerWatcherFromTyped(client.CoreV1().Nodes()),
						Transform:      transformFunc,
						QueryAll:       queryAllFunc,
					}
				},
				newTestNodeTable,
			),
			cell.Invoke(
				k8s.RegisterReflector[*corev1.Node],
				func(db_ *statedb.DB, tbl statedb.RWTable[*corev1.Node]) {
					// Insert a dummy node into the table to verify that the initial synchronization
					// cleans things up.
					// BTW, if you don't want everything cleaned up you can specify the QueryAll
					// function to "namespace" what the reflector is managing.
					wtxn := db_.WriteTxn(tbl)
					var garbageNode corev1.Node
					garbageNode.Name = "garbage"
					tbl.Insert(wtxn, &garbageNode)
					wtxn.Commit()

					db = db_
					nodeTable = tbl
				}),
		),
	)

	tlog := hivetest.Logger(t)
	if err := hive.Start(tlog, ctx); err != nil {
		t.Fatalf("hive.Start failed: %s", err)
	}

	// Wait until the table has been initialized.
	require.Eventually(
		t,
		func() bool { return nodeTable.Initialized(db.ReadTxn()) },
		time.Second,
		5*time.Millisecond)

	// After initialization we should see the node that was created
	// before starting.
	iter, watch := nodeTable.AllWatch(db.ReadTxn())
	nodes := statedb.Collect(iter)
	require.Len(t, nodes, 1)
	require.Equal(t, node1Name, nodes[0].Name)

	if doTransform {
		// Transform func set, check that it was used.
		require.Equal(t, "transformed", nodes[0].GenerateName)
	}

	// Update the node and check that it updated.
	node.Status.Phase = "update1"
	node.ObjectMeta.ResourceVersion = "1"
	fakeClient.KubernetesFakeClientset.Tracker().Update(
		corev1.SchemeGroupVersion.WithResource("nodes"),
		node.DeepCopy(), "")

	<-watch
	iter, watch = nodeTable.AllWatch(db.ReadTxn())
	nodes = statedb.Collect(iter)
	require.Len(t, nodes, 1)
	require.EqualValues(t, "update1", nodes[0].Status.Phase)

	// Create another node after initialization.
	node2 := node.DeepCopy()
	node2.ObjectMeta.Name = node2Name
	fakeClient.KubernetesFakeClientset.Tracker().Create(
		corev1.SchemeGroupVersion.WithResource("nodes"),
		node2.DeepCopy(), "")

	// Wait until updated.
	<-watch
	iter, watch = nodeTable.AllWatch(db.ReadTxn())
	nodes = statedb.Collect(iter)
	require.Len(t, nodes, 2)
	require.Equal(t, node1Name, nodes[0].Name)
	require.Equal(t, node2Name, nodes[1].Name)

	// Finally delete the nodes
	fakeClient.KubernetesFakeClientset.Tracker().Delete(
		corev1.SchemeGroupVersion.WithResource("nodes"),
		"", node1Name)

	<-watch
	iter, watch = nodeTable.AllWatch(db.ReadTxn())
	nodes = statedb.Collect(iter)
	require.Len(t, nodes, 1)
	require.EqualValues(t, node2Name, nodes[0].Name)

	fakeClient.KubernetesFakeClientset.Tracker().Delete(
		corev1.SchemeGroupVersion.WithResource("nodes"),
		"", node2Name)

	<-watch
	iter, _ = nodeTable.AllWatch(db.ReadTxn())
	nodes = statedb.Collect(iter)
	require.Len(t, nodes, 0)

	// Finally check that the hive stops correctly. Note that we're not doing this in a
	// defer to avoid potentially deadlocking on the Fatal calls.
	if err := hive.Stop(tlog, context.TODO()); err != nil {
		t.Fatalf("hive.Stop failed: %s", err)
	}

	if doTransform {
		assert.True(t, transformCalled.Load(), "provided transform func not used")
	}
	if doQueryAll {
		assert.True(t, queryAllCalled.Load(), "provided query all func not used")
	}
}

func TestStateDBReflector_jobName(t *testing.T) {
	cfg := k8s.ReflectorConfig[corev1.Node]{
		Name: "test",
	}
	assert.Equal(
		t,
		"k8s-reflector[v1.Node]/test",
		cfg.JobName(),
	)
}
