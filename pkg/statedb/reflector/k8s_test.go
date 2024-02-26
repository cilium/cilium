// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package reflector_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/goleak"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/tools/cache"

	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/hive/job"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/statedb"
	"github.com/cilium/cilium/pkg/statedb/index"
	"github.com/cilium/cilium/pkg/statedb/reflector"
	"github.com/cilium/cilium/pkg/time"
)

func TestKubernetes(t *testing.T) {
	defer goleak.VerifyNone(t)

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

	var (
		db *statedb.DB
		lw = &fakePodListerWatcher{
			watchChan: make(chan watch.Event, 100),
		}
	)

	sourceConfig := func() reflector.KubernetesConfig[*v1.Pod] {
		return reflector.KubernetesConfig[*v1.Pod]{
			ListerWatcher: lw,
			Table:         table,
		}
	}

	h := hive.New(
		statedb.Cell,
		job.Cell,
		cell.Module("test", "Test",
			cell.ProvidePrivate(sourceConfig),
			reflector.KubernetesCell[*v1.Pod](),
		),
		cell.Invoke(func(db_ *statedb.DB) {
			db_.RegisterTable(table)
			db = db_
		}),
	)

	require.NoError(t, h.Start(context.TODO()))

	// Table is empty when starting.
	txn := db.ReadTxn()
	iter, watchAll := table.All(txn)
	objs := statedb.Collect[*v1.Pod](iter)
	assert.Len(t, objs, 0)

	// Send a new pod and wait for table to update.
	expectedPod := &v1.Pod{
		TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "Pod"},
		ObjectMeta: metav1.ObjectMeta{
			Name: "pod1", Namespace: "test1",
			Labels: map[string]string{
				"foo": "bar",
			},
		},
	}
	lw.watchChan <- watch.Event{
		Type:   watch.Added,
		Object: expectedPod.DeepCopy(),
	}

	<-watchAll

	// Table should now contain the new pod
	txn = db.ReadTxn()
	iter, _ = table.All(txn)
	objs = statedb.Collect[*v1.Pod](iter)
	assert.Len(t, objs, 1)

	// Pod can be retrieved by name
	pod, _, ok := table.First(txn, podNameIndex.Query(expectedPod.Namespace+"/"+expectedPod.Name))
	if assert.True(t, ok) && assert.NotNil(t, pod) {
		assert.Equal(t, expectedPod.Name, pod.Name)
	}

	// Modify the pod and observe the update
	_, watchAll = table.All(db.ReadTxn())

	expectedPod.Labels["bar"] = "baz"
	lw.watchChan <- watch.Event{
		Type:   watch.Added,
		Object: expectedPod.DeepCopy(),
	}

	<-watchAll

	pod, _, ok = table.First(txn, podNameIndex.Query(expectedPod.Namespace+"/"+expectedPod.Name))
	if assert.True(t, ok) && assert.NotNil(t, pod) {
		assert.Equal(t, expectedPod.Name, pod.Name)
		assert.Equal(t, expectedPod.Labels["bar"], "baz")
	}

	// Pod deletion can be observed
	_, watchAll = table.All(db.ReadTxn())

	lw.watchChan <- watch.Event{
		Type:   watch.Deleted,
		Object: expectedPod.DeepCopy(),
	}

	<-watchAll

	iter, _ = table.All(db.ReadTxn())
	objs = statedb.Collect[*v1.Pod](iter)
	assert.Len(t, objs, 0)

	assert.NoError(t, h.Stop(context.TODO()))
}

type slimPod struct {
	Name, Namespace string
	Source          string
}

// TestKubernetesWithTransformAndQueryAll checks that the Transform and QueryAll options
// are properly handled. The Transform allows transforming the object received from the
// ListerWatcher to another one before it is stored. The QueryAll allows using a single
// table with multiple reflectors or other writers by namespacing them.
func TestKubernetesWithTransformAndQueryAll(t *testing.T) {
	defer goleak.VerifyNone(t)

	podNameIndex := statedb.Index[*slimPod, string]{
		Name: "name",
		FromObject: func(p *slimPod) index.KeySet {
			return index.NewKeySet(index.String(p.Namespace + "/" + p.Name))
		},
		FromKey: index.String,
		Unique:  true,
	}

	podSourceIndex := statedb.Index[*slimPod, string]{
		Name: "source",
		FromObject: func(p *slimPod) index.KeySet {
			return index.NewKeySet(index.String(p.Source))
		},
		FromKey: index.String,
		Unique:  false,
	}

	table, err := statedb.NewTable[*slimPod]("pods", podNameIndex, podSourceIndex)
	require.NoError(t, err, "NewTable")

	var (
		db *statedb.DB
		lw = &fakePodListerWatcher{
			watchChan: make(chan watch.Event, 100),
		}
	)

	sourceConfig := func() reflector.KubernetesConfig[*slimPod] {
		return reflector.KubernetesConfig[*slimPod]{
			ListerWatcher: lw,
			Table:         table,
			Transform: func(obj any) (*slimPod, bool) {
				pod := obj.(*v1.Pod)
				return &slimPod{
					Name:      pod.Name,
					Namespace: pod.Namespace,
					Source:    "k8s",
				}, true
			},
			QueryAll: func(txn statedb.ReadTxn, tbl statedb.Table[*slimPod]) statedb.Iterator[*slimPod] {
				iter, _ := tbl.Get(txn, podSourceIndex.Query("k8s"))
				return iter
			},
		}
	}

	h := hive.New(
		statedb.Cell,
		job.Cell,
		cell.Module("test", "Test",
			cell.ProvidePrivate(sourceConfig),
			reflector.KubernetesCell[*slimPod](),
		),
		cell.Invoke(func(db_ *statedb.DB) {
			db_.RegisterTable(table)
			db = db_
		}),
	)

	require.NoError(t, h.Start(context.TODO()))

	{
		txn := db.WriteTxn(table)
		// Insert some objects that are not managed by the reflector. These should be left alone.
		table.Insert(txn, &slimPod{Name: "foo", Namespace: "bar", Source: "test"})
		table.Insert(txn, &slimPod{Name: "baz", Namespace: "quux", Source: "test"})

		// Insert a "leftover" object that is managed by the reflector. This should be removed.
		table.Insert(txn, &slimPod{Name: "leftover", Namespace: "test1", Source: "k8s"})

		txn.Commit()
	}

	// Wait for the leftover pod to be removed. This is necessary, as we don't
	// have a real api-server to cover the gap between the reflectors List and
	// Watch calls. If the above transaction falls into that window, and we
	// wouldn't wait for the removal here, it's possible that the Get query
	// below would be invalidated by the removal of the leftover pod, instead
	// signalling the addition of the expected pod. On the other hand, we cannot
	// simply wait for this query to invalidate, as it is also possible that the
	// leftover pod was removed before we query, here.
	_, _, changed, leftover := table.FirstWatch(db.ReadTxn(), podNameIndex.Query("test1/leftover"))
	if leftover {
		<-changed
	}
	_, _, leftover = table.First(db.ReadTxn(), podNameIndex.Query("test1/leftover"))
	require.False(t, leftover, "leftover pod should be gone")

	_, watchAll := table.Get(db.ReadTxn(), podSourceIndex.Query("k8s"))

	// Send a new pod and wait for table to update.
	expectedPod := &v1.Pod{
		TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "Pod"},
		ObjectMeta: metav1.ObjectMeta{
			Name: "pod1", Namespace: "test1",
			Labels: map[string]string{
				"foo": "bar",
			},
		},
	}
	lw.watchChan <- watch.Event{
		Type:   watch.Added,
		Object: expectedPod.DeepCopy(),
	}

	<-watchAll

	// Table should now contain the new pod. The leftover should be gone.
	txn := db.ReadTxn()
	iter, watchAll := table.Get(db.ReadTxn(), podSourceIndex.Query("k8s"))
	objs := statedb.Collect[*slimPod](iter)
	assert.Len(t, objs, 1)

	// Pod can be retrieved by name
	pod, _, ok := table.First(txn, podNameIndex.Query(expectedPod.Namespace+"/"+expectedPod.Name))
	if assert.True(t, ok) && assert.NotNil(t, pod) {
		assert.Equal(t, expectedPod.Name, pod.Name)
	}

	// Pod deletion can be observed
	lw.watchChan <- watch.Event{
		Type:   watch.Deleted,
		Object: expectedPod.DeepCopy(),
	}

	<-watchAll

	iter, _ = table.Get(db.ReadTxn(), podSourceIndex.Query("k8s"))
	objs = statedb.Collect[*slimPod](iter)
	assert.Len(t, objs, 0)

	// The objects from the other source should not have been touched.
	iter, _ = table.Get(db.ReadTxn(), podSourceIndex.Query("test"))
	objs = statedb.Collect[*slimPod](iter)
	assert.Len(t, objs, 2)

	assert.NoError(t, h.Stop(context.TODO()))
}

// BenchmarkKubernetes uses the fake client to benchmark how many objects per second
// we can insert into a StateDB table.
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

	// To make this slightly more realistic, also index the labels. This
	// is a secondary index with 3 entries (labels) per object.
	// This does have a significant impact on throughput, on my machine I get
	// ~365k/s without this index and ~150k/s with the index. So we do need
	// to be careful in how eagerly we index things and may often want to do
	// filtering on iteration instead (e.g. a control-plane controller should
	// likely watch all changes by revision and skip uninteresting things rather
	// than have an indexing on the interesting fields).
	podLabelsIndex := statedb.Index[*v1.Pod, string]{
		Name: "labels",
		FromObject: func(p *v1.Pod) index.KeySet {
			keys := make([]index.Key, 0, len(p.Labels))
			for k, v := range p.Labels {
				keys = append(keys, index.String(k+"="+v))
			}
			return index.NewKeySet(keys...)
		},
		FromKey: index.String,
		Unique:  false,
	}

	table, err := statedb.NewTable[*v1.Pod]("pods", podNameIndex, podLabelsIndex)
	require.NoError(b, err, "NewTable")

	// batchSize is the number of objects that we update and the number that are committed
	// in one write transaction.
	batchSize := 100

	lw := &fakePodListerWatcher{
		watchChan: make(chan watch.Event, batchSize),
	}

	sourceConfig := func() reflector.KubernetesConfig[*v1.Pod] {
		return reflector.KubernetesConfig[*v1.Pod]{
			BufferSize:     batchSize,
			BufferWaitTime: 100 * time.Millisecond,
			ListerWatcher:  lw,
			Table:          table,
		}
	}

	var db *statedb.DB

	h := hive.New(
		statedb.Cell,
		job.Cell,
		cell.Module("test", "Test",
			cell.ProvidePrivate(sourceConfig),
			reflector.KubernetesCell[*v1.Pod](),
		),
		cell.Invoke(func(db_ *statedb.DB) {
			db_.RegisterTable(table)
			db = db_
		}),
	)

	generation := int64(1)

	pod := &v1.Pod{
		TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "Pod"},
		ObjectMeta: metav1.ObjectMeta{
			Name: "pod1", Namespace: "test1",
			Labels: map[string]string{
				"foo": "bar",
				"baz": "quux",
			},
		},
	}

	// Create the initial pods (e.g. what List() returns)
	for j := 0; j < batchSize; j++ {
		pod.Name = fmt.Sprintf("pod%d", j)
		pod.Namespace = "test1"
		pod.ResourceVersion = fmt.Sprintf("%d", generation)
		pod.Generation = generation
		generation++
		pod.UID = types.UID(pod.Name)
		lw.initial = append(lw.initial, *pod.DeepCopy())
	}

	require.NoError(b, h.Start(context.TODO()))

	// Wait for the initial pods to be created
	iter, watchAll := table.All(db.ReadTxn())
	for {
		objs := statedb.Collect[*v1.Pod](iter)
		if len(objs) == batchSize {
			break
		}
		<-watchAll
		iter, watchAll = table.All(db.ReadTxn())
	}

	// Benchmark updating a batch of objects b.N times.
	b.ResetTimer()
	lastLabelI := ""
	for i := 0; i < b.N; i++ {
		lastLabelI = fmt.Sprintf("%d", i)
		pod.Labels["i"] = lastLabelI
		for j := 0; j < batchSize; j++ {
			pod.Name = fmt.Sprintf("pod%d", j)
			pod.Namespace = "test1"
			pod.UID = types.UID(pod.Name)
			pod.ResourceVersion = fmt.Sprintf("%d", generation)
			pod.Generation = generation
			generation++

			lw.watchChan <- watch.Event{
				Type:   watch.Modified,
				Object: pod.DeepCopy(),
			}
		}

		// Wait until the whole batch has been processed. If we would not wait here,
		// then updates would get coalesced by stream.Buffer. This of course does
		// slightly decrease the measured throughput.
	waitLoop:
		for {
			<-watchAll
			iter, watchAll = table.All(db.ReadTxn())

			objs := statedb.Collect[*v1.Pod](iter)
			if len(objs) != batchSize {
				continue
			}
			// Check that all objects have the final state.
			for _, obj := range objs {
				if obj.Labels["i"] != lastLabelI {
					continue waitLoop
				}
			}
			break
		}

	}
	b.StopTimer()
	b.ReportMetric(float64(batchSize)*float64(b.N)/b.Elapsed().Seconds(), "objects/sec")
}

// A fake lister watcher to have full control over what List and Watch returns.
// The k8s-client's fake client has a fixed buffer size and we'd have to be careful
// with timing as it holds no state, so instead we're faking it at this level. This
// also provides a better baseline number for the benchmarking.
type fakePodListerWatcher struct {
	initial   []v1.Pod
	watchChan chan watch.Event
}

// List implements cache.ListerWatcher.
func (lw *fakePodListerWatcher) List(options metav1.ListOptions) (runtime.Object, error) {
	return &v1.PodList{
		TypeMeta: metav1.TypeMeta{
			Kind:       "PodList",
			APIVersion: "v1",
		},
		ListMeta: metav1.ListMeta{
			ResourceVersion:    "1",
			Continue:           "",
			RemainingItemCount: new(int64),
		},
		Items: lw.initial,
	}, nil
}

// Watch implements cache.ListerWatcher.
func (lw *fakePodListerWatcher) Watch(options metav1.ListOptions) (watch.Interface, error) {
	return lw, nil
}

// ResultChan implements watch.Interface.
func (lw *fakePodListerWatcher) ResultChan() <-chan watch.Event {
	return lw.watchChan
}

// Stop implements watch.Interface.
func (lw *fakePodListerWatcher) Stop() {
}

var _ cache.ListerWatcher = &fakePodListerWatcher{}
var _ watch.Interface = &fakePodListerWatcher{}
