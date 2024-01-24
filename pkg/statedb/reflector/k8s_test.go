// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package reflector_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/hive/job"
	"github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/utils"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/statedb"
	"github.com/cilium/cilium/pkg/statedb/index"
	"github.com/cilium/cilium/pkg/statedb/reflector"
)

func TestKubernetes(t *testing.T) {
	podNameIndex := statedb.Index[*v1.Pod, string]{
		Name: "name",
		FromObject: func(p *v1.Pod) index.KeySet {
			return index.NewKeySet(index.String(p.Namespace + "/" + p.Name))
		},
		FromKey: index.String,
		Unique:  true,
	}

	table, err := statedb.NewTable[*v1.Pod]("pods", podNameIndex)
	require.NoError(t, err, "NewTable")

	type params struct {
		cell.In

		DB        *statedb.DB
		Clientset client.Clientset
	}
	var p params

	sourceConfig := func(cs client.Clientset) reflector.KubernetesConfig[*v1.Pod] {
		lw := utils.ListerWatcherFromTyped[*v1.PodList](
			cs.CoreV1().Pods(""),
		)

		return reflector.KubernetesConfig[*v1.Pod]{
			ListerWatcher: lw,
			Table:         table,
		}
	}

	h := hive.New(
		statedb.Cell,
		job.Cell,
		client.FakeClientCell,

		cell.Module("test", "Test",
			cell.ProvidePrivate(sourceConfig),
			reflector.KubernetesCell[*v1.Pod](),

			cell.Invoke(
				func(db *statedb.DB) error {
					return db.RegisterTable(table)
				}),

			cell.Invoke(func(p_ params) { p = p_ }),
		),
	)

	require.NoError(t, h.Start(context.TODO()))

	// Table is empty when starting.
	txn := p.DB.ReadTxn()
	iter, watch := table.All(txn)
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
	require.NoError(t, err, "Create pod")

	<-watch

	// Table should now contain the new pod
	txn = p.DB.ReadTxn()
	iter, _ = table.All(txn)
	objs = statedb.Collect[*v1.Pod](iter)
	assert.Len(t, objs, 1)

	// Pod can be retrieved by name
	pod, _, ok := table.First(txn, podNameIndex.Query(expectedPod.Namespace+"/"+expectedPod.Name))
	if assert.True(t, ok) && assert.NotNil(t, pod) {
		assert.Equal(t, expectedPod.Name, pod.Name)
	}

	// Pod deletion can be observed
	_, watch = table.All(txn)
	err = p.Clientset.CoreV1().Pods("test1").Delete(context.Background(), "pod1", metav1.DeleteOptions{})
	if !assert.NoError(t, err) {
		t.FailNow()
	}
	<-watch

	iter, _ = table.All(p.DB.ReadTxn())
	objs = statedb.Collect[*v1.Pod](iter)
	assert.Len(t, objs, 0)

	assert.NoError(t, h.Stop(context.TODO()))
}

func BenchmarkKubernetes(b *testing.B) {
	logging.SetLogLevel(logrus.WarnLevel)

	podNameIndex := statedb.Index[*v1.Pod, string]{
		Name: "name",
		FromObject: func(p *v1.Pod) index.KeySet {
			return index.NewKeySet(index.String(p.Namespace + "/" + p.Name))
		},
		FromKey: index.String,
		Unique:  true,
	}

	table, err := statedb.NewTable[*v1.Pod]("pods", podNameIndex)
	require.NoError(b, err, "NewTable")

	type params struct {
		cell.In

		DB        *statedb.DB
		Clientset client.Clientset
	}
	var p params

	// Don't use a buffer size larger than 100 since that's the limit
	// for how much the fake client wants to buffer.
	batchSize := 100

	sourceConfig := func(cs client.Clientset) reflector.KubernetesConfig[*v1.Pod] {
		lw := utils.ListerWatcherFromTyped[*v1.PodList](
			cs.CoreV1().Pods(""),
		)

		return reflector.KubernetesConfig[*v1.Pod]{
			BufferSize:     batchSize,
			BufferWaitTime: time.Hour, // We want to only emit on full buffer
			ListerWatcher:  lw,
			Table:          table,
		}
	}

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

	h := hive.New(
		statedb.Cell,
		job.Cell,
		client.FakeClientCell,

		cell.Invoke(func(cs client.Clientset) {
			// Create the initial pods before anything starts. The fake client
			// doesn't know how to "Watch" from a specific ResourceVersion so we
			// need to make sure that we've added everything before Watch() gets called.
			for j := 0; j < batchSize; j++ {
				expectedPod.ObjectMeta.Name = fmt.Sprintf("pod%d", j)
				expectedPod.ObjectMeta.ResourceVersion = "1"
				expectedPod.ObjectMeta.Generation = 1
				expectedPod.UID = types.UID(expectedPod.Name)
				_, err = cs.CoreV1().Pods("test1").Create(
					context.Background(), expectedPod.DeepCopy(), metav1.CreateOptions{})
				require.NoError(b, err, "Create pod")
			}
		}),

		cell.Module("test", "Test",
			cell.ProvidePrivate(sourceConfig),
			reflector.KubernetesCell[*v1.Pod](),

			cell.Invoke(
				func(db *statedb.DB) error {
					return db.RegisterTable(table)
				}),

			cell.Invoke(func(p_ params) { p = p_ }),
		),
	)

	require.NoError(b, h.Start(context.TODO()))

	// Wait for pods to be created
	iter, watch := table.All(p.DB.ReadTxn())
	for {
		objs := statedb.Collect[*v1.Pod](iter)
		if len(objs) == batchSize {
			break
		}
		<-watch
		iter, watch = table.All(p.DB.ReadTxn())
	}

	// Benchmark updating a batch of objects and checking that the table
	// has updated. Actual throughput is 'batchSize' * the number of iterations
	// in a second. On my i5 laptop I'm getting ~120k/s with batchSize of 100.

	b.Logf("batchSize=%d, multiple the ops/sec with it for per-object throughput", batchSize)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		expectedPod.ResourceVersion = fmt.Sprintf("%d", i+2)
		expectedPod.Generation = int64(i + 1)
		expectedPod.Labels["i"] = fmt.Sprintf("%d", i)
		for j := 0; j < batchSize; j++ {
			expectedPod.Name = fmt.Sprintf("pod%d", j)
			expectedPod.UID = types.UID(expectedPod.Name)
			_, err = p.Clientset.CoreV1().Pods("test1").Update(
				context.Background(), expectedPod.DeepCopy(), metav1.UpdateOptions{})
			require.NoError(b, err, "Update pod")
		}

		// Wait until the batch has committed.
		<-watch

		// Check that all objects are from the new round
		iter, watch1 := table.All(p.DB.ReadTxn())
		watch = watch1
		objs := statedb.Collect[*v1.Pod](iter)
		require.Len(b, objs, batchSize)
		for _, obj := range objs {
			require.Equal(b, obj.Labels["i"], fmt.Sprintf("%d", i))
		}

	}
}
