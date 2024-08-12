// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package testutils

import (
	"testing"

	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/api/meta"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/watch"

	"github.com/cilium/cilium/pkg/inctimer"
	cilium_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/time"
)

func TestFakeListerWatcher(t *testing.T) {
	lw := NewFakeListerWatcher()

	// Fake always returns an empty list.
	obj, err := lw.List(v1.ListOptions{})
	require.NoError(t, err, "List")

	// The returned "List" object should be iterable with the meta tooling.
	// (side-note: this will reflect on the object to find "Items" field).
	meta.EachListItem(obj, func(o runtime.Object) error {
		t.Fatalf("Unexpected callback in EachListItem")
		return nil
	})

	watcher, err := lw.Watch(v1.ListOptions{})
	require.NoError(t, err, "Watch")

	results := watcher.ResultChan()

	// There should be nothing yet.
	select {
	case obj := <-results:
		t.Fatalf("unexpected object in ResultChan: %v", obj)
	default:
	}

	// Insert an object via file.
	err = lw.UpsertFromFile("testdata/ciliumnode.yaml")
	require.NoError(t, err, "UpsertFromFile ciliumnode.yaml")

	// We should be now able to receive the object
	select {
	case ev := <-results:
		require.Equal(t, ev.Type, watch.Added)
		obj := ev.Object
		require.NotNil(t, obj, "object nil")
		require.IsType(t, &cilium_v2.CiliumNode{}, obj)
	case <-inctimer.After(time.Second):
		t.Fatalf("timed out waiting for object")
	}

	// Second time we'll get a modify.
	err = lw.UpsertFromFile("testdata/ciliumnode.yaml")
	require.NoError(t, err, "UpsertFromFile ciliumnode.yaml")
	select {
	case ev := <-results:
		require.Equal(t, ev.Type, watch.Modified)
		obj := ev.Object
		require.NotNil(t, obj, "object nil")
		require.IsType(t, &cilium_v2.CiliumNode{}, obj)
	case <-inctimer.After(time.Second):
		t.Fatalf("timed out waiting for object")
	}

	err = lw.DeleteFromFile("testdata/ciliumnode.yaml")
	require.NoError(t, err, "DeleteFromFile ciliumnode.yaml")

	select {
	case ev := <-results:
		require.Equal(t, ev.Type, watch.Deleted)
		obj := ev.Object
		require.NotNil(t, obj, "object nil")
		require.IsType(t, &cilium_v2.CiliumNode{}, obj)
	case <-inctimer.After(time.Second):
		t.Fatalf("timed out waiting for object")
	}

	watcher.Stop()
}
