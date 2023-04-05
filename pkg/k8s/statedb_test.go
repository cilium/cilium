// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package k8s_test

import (
	"context"
	"testing"

	"github.com/hashicorp/go-memdb"
	"github.com/stretchr/testify/assert"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/cache"

	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/k8s"
	"github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/utils"
	"github.com/cilium/cilium/pkg/statedb"
)

// TODO also test with v1.Node or some other non-namespaced object.

// byLabels is a query for the custom index we defined for querying
// pods by labels.
func byLabel(key, value string) statedb.Query {
	return statedb.Query{Index: "labels", Args: []any{key, value}}
}

func TestK8sTableCell(t *testing.T) {
	type params struct {
		cell.In

		DB        statedb.DB
		Table     statedb.ReadOnlyTable[*v1.Pod]
		Clientset client.Clientset
	}
	var p params

	h := hive.New(
		client.FakeClientCell,
		statedb.Cell,
		k8s.NewK8sTableCell[*v1.Pod](
			"pods",
			func(cs client.Clientset) cache.ListerWatcher {
				return utils.ListerWatcherFromTyped[*v1.PodList](
					cs.CoreV1().Pods(""),
				)
			},

			// Index pods also by labels
			&memdb.IndexSchema{
				Name:         "labels",
				AllowMissing: true,
				Unique:       false,
				Indexer:      &memdb.StringMapFieldIndex{Field: "Labels"},
			},
		),
		cell.Invoke(func(p_ params) { p = p_ }),
	)

	if !assert.NoError(t, h.Start(context.TODO())) {
		t.FailNow()
	}

	// Table is empty when starting.
	iter, err := p.Table.Reader(p.DB.ReadTxn()).Get(statedb.All)
	assert.NoError(t, err)
	objs := statedb.Collect[*v1.Pod](iter)
	assert.Len(t, objs, 0)

	// Insert a new pod and wait for table to update.
	expectedPod := &v1.Pod{
		TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "Pod"},
		ObjectMeta: metav1.ObjectMeta{
			Name: "pod1", Namespace: "test1",
			Labels: map[string]string{
				"foo": "bar",
			},
		},
	}
	_, err = p.Clientset.CoreV1().Pods("test1").Create(
		context.Background(), expectedPod, metav1.CreateOptions{})
	if !assert.NoError(t, err) {
		t.FailNow()
	}

	<-iter.Invalidated()

	// Table should now contain the new pod
	reader := p.Table.Reader(p.DB.ReadTxn())
	iter, err = reader.Get(statedb.All)
	assert.NoError(t, err)
	objs = statedb.Collect[*v1.Pod](iter)
	assert.Len(t, objs, 1)

	// Pod can be retrieved by name
	pod, err := reader.First(k8s.ByName(expectedPod.Namespace, expectedPod.Name))
	if assert.NoError(t, err) && assert.NotNil(t, pod) {
		assert.Equal(t, expectedPod.Name, pod.Name)
	}

	// Pod can be retrieved by namespace
	iter, err = reader.Get(k8s.ByNamespace("test1"))
	if assert.NoError(t, err) {
		objs = statedb.Collect[*v1.Pod](iter)
		if assert.Len(t, objs, 1) {
			assert.Equal(t, expectedPod.Name, objs[0].Name)
		}
	}

	iter, err = reader.Get(k8s.ByNamespace("test2"))
	if assert.NoError(t, err) {
		objs = statedb.Collect[*v1.Pod](iter)
		assert.Len(t, objs, 0)
	}

	// Pod can be retrieved via label
	iter, err = reader.Get(byLabel("foo", "bar"))
	if assert.NoError(t, err) {
		objs = statedb.Collect[*v1.Pod](iter)
		assert.Len(t, objs, 1)
	}

	iter, err = reader.Get(byLabel("bar", "quux"))
	if assert.NoError(t, err) {
		objs = statedb.Collect[*v1.Pod](iter)
		assert.Len(t, objs, 0)
	}

	// Pod deletion can be observed
	iter, err = reader.Get(statedb.All)
	err = p.Clientset.CoreV1().Pods("test1").Delete(context.Background(), "pod1", metav1.DeleteOptions{})
	if !assert.NoError(t, err) {
		t.FailNow()
	}
	<-iter.Invalidated()

	reader = p.Table.Reader(p.DB.ReadTxn())
	iter, err = reader.Get(statedb.All)
	if assert.NoError(t, err) {
		objs = statedb.Collect[*v1.Pod](iter)
		assert.Len(t, objs, 0)
	}

	assert.NoError(t, h.Stop(context.TODO()))
}
