// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package testutils

import (
	"log/slog"
	"strconv"
	"testing"
	"time"

	"github.com/cilium/hive/hivetest"
	"github.com/cilium/statedb"
	"github.com/stretchr/testify/require"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/watch"

	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	v1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
)

func TestStateDBObjectTracker_fillTypeMeta(t *testing.T) {
	db := statedb.New()
	log := hivetest.Logger(t, hivetest.LogLevel(slog.LevelDebug))

	ot, err := newStateDBObjectTracker(db, log)
	require.NoError(t, err)

	gvr := schema.GroupVersionResource{
		Group:    "",
		Version:  "v1",
		Resource: "nodes",
	}

	// A node without the TypeMeta.
	node := v1.Node{
		ObjectMeta: slim_metav1.ObjectMeta{Name: "test1"},
	}

	// Add() an object
	err = ot.Add(node.DeepCopy())
	require.NoError(t, err, "Add")

	nodeAny, err := ot.Get(gvr, "", "test1")
	require.NoError(t, err)
	n := nodeAny.(*v1.Node)
	require.Equal(t, "Node", n.TypeMeta.Kind)
	require.Equal(t, "v1", n.TypeMeta.APIVersion)
	require.Equal(t, "1", n.GetResourceVersion())

	node.Name = "test2"

	err = ot.Create(gvr, node.DeepCopy(), "")
	require.NoError(t, err, "Create")
	nodeAny, err = ot.Get(gvr, "", "test2")
	require.NoError(t, err)
	n = nodeAny.(*v1.Node)
	require.Equal(t, "Node", n.TypeMeta.Kind)
	require.Equal(t, "v1", n.TypeMeta.APIVersion)
	require.Equal(t, "2", n.GetResourceVersion())

	update := node.DeepCopy()
	update.SetResourceVersion(n.GetResourceVersion())
	err = ot.Update(gvr, update, "")
	require.NoError(t, err, "Update")
	nodeAny, err = ot.Get(gvr, "", "test2")
	require.NoError(t, err)
	n = nodeAny.(*v1.Node)
	require.Equal(t, "Node", n.TypeMeta.Kind)
	require.Equal(t, "v1", n.TypeMeta.APIVersion)
	require.Equal(t, "3", n.GetResourceVersion())

	// A cilium node without the TypeMeta. This tests that the
	// APIVersion is correctly set when Group is non-empty.
	ciliumNode := ciliumv2.CiliumNode{
		ObjectMeta: metav1.ObjectMeta{Name: "test1"},
	}

	gvr = schema.GroupVersionResource{
		Group:    "cilium.io",
		Version:  "v2",
		Resource: "ciliumnodes",
	}
	err = ot.Add(ciliumNode.DeepCopy())
	require.NoError(t, err, "Add")

	ciliumNodeAny, err := ot.Get(gvr, "", "test1")
	require.NoError(t, err)
	cn := ciliumNodeAny.(*ciliumv2.CiliumNode)
	require.Equal(t, "CiliumNode", cn.TypeMeta.Kind)
	require.Equal(t, "cilium.io/v2", cn.TypeMeta.APIVersion)
	require.Equal(t, "4", cn.GetResourceVersion())

}

func TestStateDBObjectTracker_ResyncInjectsExpiredWatchError(t *testing.T) {
	db := statedb.New()
	log := hivetest.Logger(t, hivetest.LogLevel(slog.LevelDebug))

	ot, err := newStateDBObjectTracker(db, log)
	require.NoError(t, err)

	svc := &v1.Service{
		ObjectMeta: slim_metav1.ObjectMeta{
			Name:      "echo",
			Namespace: "test",
		},
	}
	require.NoError(t, ot.Add(svc))
	rv := strconv.FormatUint(ot.tbl.Revision(ot.db.ReadTxn()), 10)

	gvr := schema.GroupVersionResource{
		Group:    "",
		Version:  "v1",
		Resource: "services",
	}

	watchAll, err := ot.Watch(gvr, "", metav1.ListOptions{ResourceVersion: rv})
	require.NoError(t, err)
	t.Cleanup(watchAll.Stop)

	watchOtherNS, err := ot.Watch(gvr, "other", metav1.ListOptions{ResourceVersion: rv})
	require.NoError(t, err)
	t.Cleanup(watchOtherNS.Stop)

	stopped, rev, err := ot.Resync(gvr, nil)
	require.NoError(t, err)
	require.Equal(t, 2, stopped)
	require.GreaterOrEqual(t, rev, statedb.Revision(1))

	ev := requireWatchEvent(t, watchAll.ResultChan())
	require.Equal(t, watch.Error, ev.Type)
	status, ok := ev.Object.(*metav1.Status)
	require.True(t, ok, "expected watch error object to be *metav1.Status")
	require.True(t, apierrors.IsResourceExpired(apierrors.FromObject(status)))
	ev = requireWatchEvent(t, watchOtherNS.ResultChan())
	require.Equal(t, watch.Error, ev.Type)
	status, ok = ev.Object.(*metav1.Status)
	require.True(t, ok, "expected watch error object to be *metav1.Status")
	require.True(t, apierrors.IsResourceExpired(apierrors.FromObject(status)))

	_, err = ot.Watch(gvr, "test", metav1.ListOptions{ResourceVersion: rv})
	require.Error(t, err)
	require.True(t, apierrors.IsResourceExpired(err))

	freshRV := strconv.FormatUint(uint64(rev), 10)
	freshWatch, err := ot.Watch(gvr, "test", metav1.ListOptions{ResourceVersion: freshRV})
	require.NoError(t, err)
	t.Cleanup(freshWatch.Stop)

	watchList, err := ot.Watch(gvr, "test", metav1.ListOptions{ResourceVersion: "0"})
	require.NoError(t, err)
	t.Cleanup(watchList.Stop)
}

func requireWatchEvent(t *testing.T, ch <-chan watch.Event) watch.Event {
	t.Helper()
	select {
	case ev, ok := <-ch:
		require.True(t, ok, "expected watch event")
		return ev
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for watch event")
	}
	return watch.Event{}
}
