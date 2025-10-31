// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package testutils

import (
	"log/slog"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/cilium/statedb"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"

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

	node.Name = "test2"

	err = ot.Create(gvr, node.DeepCopy(), "")
	require.NoError(t, err, "Create")
	nodeAny, err = ot.Get(gvr, "", "test2")
	require.NoError(t, err)
	n = nodeAny.(*v1.Node)
	require.Equal(t, "Node", n.TypeMeta.Kind)
	require.Equal(t, "v1", n.TypeMeta.APIVersion)

	err = ot.Update(gvr, node.DeepCopy(), "")
	require.NoError(t, err, "Update")
	nodeAny, err = ot.Get(gvr, "", "test2")
	require.NoError(t, err)
	n = nodeAny.(*v1.Node)
	require.Equal(t, "Node", n.TypeMeta.Kind)
	require.Equal(t, "v1", n.TypeMeta.APIVersion)

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

}
