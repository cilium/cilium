// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package resource_test

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8sRuntime "k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"

	"github.com/cilium/cilium/pkg/hive"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	k8sFakeClient "github.com/cilium/cilium/pkg/k8s/client/testutils"
	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/lock"
)

type fakeResource[T k8sRuntime.Object] struct {
	events chan resource.Event[T]
	store  resource.Store[T]
}

func (f *fakeResource[T]) Events(ctx context.Context, opts ...resource.EventsOpt) <-chan resource.Event[T] {
	return f.events
}

func (f *fakeResource[T]) Store(ctx context.Context) (resource.Store[T], error) {
	return f.store, nil
}

func (f *fakeResource[T]) Observe(ctx context.Context, next func(resource.Event[T]), complete func(error)) {
	for ev := range f.events {
		next(ev)
	}
	complete(nil)
}

type fakeStore[T k8sRuntime.Object] struct {
	items []T
}

func (f *fakeStore[T]) List() []T {
	return f.items
}

func (f *fakeStore[T]) IterKeys() resource.KeyIter {
	keys := make([]string, 0, len(f.items))
	for _, item := range f.items {
		// Use cache.MetaNamespaceKeyFunc or simple Name check since fakeStore assumes simple objects
		obj, _ := any(item).(metav1.Object)
		if obj != nil {
			keys = append(keys, obj.GetName())
		}
	}
	return &fakeKeyIter{keys: keys, pos: -1}
}

type fakeKeyIter struct {
	keys []string
	pos  int
}

func (it *fakeKeyIter) Next() bool {
	it.pos++
	return it.pos < len(it.keys)
}

func (it *fakeKeyIter) Key() resource.Key {
	return resource.Key{Name: it.keys[it.pos]}
}

func (f *fakeStore[T]) Get(obj T) (item T, exists bool, err error) {
	return *new(T), false, nil
}

func (f *fakeStore[T]) GetByKey(key resource.Key) (item T, exists bool, err error) {
	for _, item := range f.items {
		obj, ok := any(item).(metav1.Object)
		if !ok {
			continue
		}
		if obj.GetName() == key.Name {
			return item, true, nil
		}
	}
	return *new(T), false, nil
}

func (f *fakeStore[T]) IndexKeys(indexName, indexedValue string) ([]string, error) {
	if indexName == "all" {
		keys := []string{}
		for _, item := range f.items {
			obj, _ := any(item).(metav1.Object)
			keys = append(keys, obj.GetName())
		}
		return keys, nil
	}
	return nil, nil
}

func (f *fakeStore[T]) ByIndex(indexName, indexedValue string) ([]T, error) {
	return nil, nil
}

func (f *fakeStore[T]) CacheStore() cache.Store {
	return nil
}

type testObject struct {
	metav1.TypeMeta
	metav1.ObjectMeta
}

func (t *testObject) DeepCopyObject() k8sRuntime.Object {
	return t
}

func TestFilteringResource_Events(t *testing.T) {
	type args struct {
		events []resource.Event[*testObject]
	}
	tests := []struct {
		name     string
		args     args
		filter   func(*testObject) bool
		expected []resource.Event[*testObject]
	}{
		{
			name: "mixed_events",
			args: args{
				events: []resource.Event[*testObject]{
					{
						Kind: resource.Sync,
						Done: func(error) {},
					},
					{
						Kind:   resource.Upsert,
						Object: &testObject{ObjectMeta: metav1.ObjectMeta{Name: "keep"}},
						Done:   func(error) {},
					},
					{
						Kind:   resource.Upsert,
						Object: &testObject{ObjectMeta: metav1.ObjectMeta{Name: "drop"}},
						Done:   func(error) {},
					},
					{
						Kind:   resource.Delete,
						Object: &testObject{ObjectMeta: metav1.ObjectMeta{Name: "keep"}},
						Done:   func(error) {},
					},
				},
			},
			filter: func(obj *testObject) bool {
				return obj.Name == "keep"
			},
			expected: []resource.Event[*testObject]{
				{
					Kind: resource.Sync,
				},
				{
					Kind:   resource.Upsert,
					Object: &testObject{ObjectMeta: metav1.ObjectMeta{Name: "keep"}},
				},
				{
					Kind:   resource.Delete,
					Object: &testObject{ObjectMeta: metav1.ObjectMeta{Name: "keep"}},
				},
			},
		},
		{
			name: "sync_only",
			args: args{
				events: []resource.Event[*testObject]{
					{
						Kind: resource.Sync,
						Done: func(error) {},
					},
				},
			},
			filter: func(obj *testObject) bool {
				return false
			},
			expected: []resource.Event[*testObject]{
				{
					Kind: resource.Sync,
				},
			},
		},
		{
			name: "all_dropped",
			args: args{
				events: []resource.Event[*testObject]{
					{
						Kind:   resource.Upsert,
						Object: &testObject{ObjectMeta: metav1.ObjectMeta{Name: "drop"}},
						Done:   func(error) {},
					},
				},
			},
			filter: func(obj *testObject) bool {
				return false
			},
			expected: []resource.Event[*testObject]{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			events := make(chan resource.Event[*testObject], len(tt.args.events))
			store := &fakeStore[*testObject]{}
			fake := &fakeResource[*testObject]{
				events: events,
				store:  store,
			}

			r := resource.NewFilteringResource[*testObject](fake, tt.filter)

			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()

			filteredEvents := r.Events(ctx)

			for _, ev := range tt.args.events {
				events <- ev
			}
			close(events)

			var received []resource.Event[*testObject]
			for ev := range filteredEvents {
				received = append(received, ev)
				ev.Done(nil)
			}

			require.Len(t, received, len(tt.expected))
			for i, expected := range tt.expected {
				assert.Equal(t, expected.Kind, received[i].Kind)
				if expected.Object != nil {
					assert.Equal(t, expected.Object.Name, received[i].Object.Name)
				}
			}
		})
	}
}

func TestFilteringResource_Observe(t *testing.T) {
	tests := []struct {
		name     string
		events   []resource.Event[*testObject]
		filter   func(*testObject) bool
		expected []string // Names of objects expected to be observed
	}{
		{
			name: "match_and_mismatch",
			events: []resource.Event[*testObject]{
				{
					Kind:   resource.Upsert,
					Object: &testObject{ObjectMeta: metav1.ObjectMeta{Name: "keep"}},
					Done:   func(error) {},
				},
				{
					Kind:   resource.Upsert,
					Object: &testObject{ObjectMeta: metav1.ObjectMeta{Name: "drop"}},
					Done:   func(error) {},
				},
			},
			filter: func(obj *testObject) bool {
				return obj.Name == "keep"
			},
			expected: []string{"keep"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			events := make(chan resource.Event[*testObject], len(tt.events))
			store := &fakeStore[*testObject]{}
			fake := &fakeResource[*testObject]{
				events: events,
				store:  store,
			}

			r := resource.NewFilteringResource[*testObject](fake, tt.filter)

			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()

			for _, ev := range tt.events {
				events <- ev
			}
			close(events)

			var wg sync.WaitGroup
			wg.Add(1)

			var observed []string
			var mu lock.Mutex

			r.Observe(ctx, func(ev resource.Event[*testObject]) {
				mu.Lock()
				observed = append(observed, ev.Object.Name)
				mu.Unlock()
				ev.Done(nil)
			}, func(err error) {
				assert.NoError(t, err)
				wg.Done()
			})

			wg.Wait()
			assert.Equal(t, tt.expected, observed)
		})
	}
}

func TestFilteringResource_Observe_context_cancel(t *testing.T) {
	store := &fakeStore[*testObject]{}
	fake := &fakeResource[*testObject]{
		events: make(chan resource.Event[*testObject]),
		store:  store,
	}

	r := resource.NewFilteringResource[*testObject](fake, func(obj *testObject) bool {
		return true
	})

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	var wg sync.WaitGroup
	wg.Add(1)

	// Start Observe in background
	go r.Observe(ctx, func(ev resource.Event[*testObject]) {
		ev.Done(nil)
	}, func(err error) {
		wg.Done()
	})

	cancel() // Cancel immediately/shortly

	// We don't push events to blockingEvents, so Observe only returns if ctx is Done
	wg.Wait()
}

func TestFilteredResource_WithFakeClient(t *testing.T) {
	var (
		nodeName = "some-node"
		node     = &corev1.Node{
			ObjectMeta: metav1.ObjectMeta{
				Name:       nodeName,
				Generation: 0,
			},
			Status: corev1.NodeStatus{
				Phase: "init",
			},
		}
		node2 = &corev1.Node{
			ObjectMeta: metav1.ObjectMeta{
				Name:       "another-node",
				Generation: 0,
			},
			Status: corev1.NodeStatus{
				Phase: "init",
			},
		}
		fakeClient, cs = k8sFakeClient.NewFakeClientset(hivetest.Logger(t))

		nodes  resource.Resource[*corev1.Node]
		events <-chan resource.Event[*corev1.Node]

		filteredNodes  resource.FilteredResource[*corev1.Node]
		filteredEvents <-chan resource.Event[*corev1.Node]
	)

	// Create the initial version of the node. Do this before anything
	// starts watching the resources to avoid a race.
	ctx, cancel := context.WithTimeout(t.Context(), testTimeout)
	defer cancel()

	curr, err := fakeClient.KubernetesFakeClientset.CoreV1().Nodes().Create(
		ctx,
		node.DeepCopy(), metav1.CreateOptions{})
	require.NoError(t, err, "Nodes.Create")

	curr2, err := fakeClient.KubernetesFakeClientset.CoreV1().Nodes().Create(
		ctx,
		node2.DeepCopy(), metav1.CreateOptions{})
	require.NoError(t, err, "Nodes.Create")

	hive := hive.New(
		cell.Provide(func() k8sClient.Clientset { return cs }),
		nodesResource,
		nodesFilteredResource,
		cell.Invoke(func(r resource.Resource[*corev1.Node]) {
			nodes = r

			events = nodes.Events(ctx)
		}),
		cell.Invoke(func(r resource.FilteredResource[*corev1.Node]) {
			filteredNodes = r

			filteredEvents = filteredNodes.Events(ctx)
		}))

	tlog := hivetest.Logger(t)
	if err := hive.Start(tlog, ctx); err != nil {
		t.Fatalf("hive.Start failed: %s", err)
	}

	normalCompare := func(nn string) bool { return nn == "another-node" || nn == nodeName }
	filteredCompare := func(nn string) bool { return nn == nodeName }

	// First event should be the node (initial set)
	expectUpsert(t, events, normalCompare, node.Status.Phase)
	expectUpsert(t, events, normalCompare, node.Status.Phase)
	expectUpsert(t, filteredEvents, filteredCompare, node.Status.Phase)

	// Second should be a sync.
	expectSync(t, events)
	expectSync(t, filteredEvents)

	// Update the node and check the update event
	node.Status.Phase = "update1"
	node.ObjectMeta.ResourceVersion = curr.ResourceVersion

	node2.Status.Phase = "update1"
	node2.ObjectMeta.ResourceVersion = curr2.ResourceVersion

	curr, err = fakeClient.KubernetesFakeClientset.CoreV1().Nodes().Update(
		ctx,
		node.DeepCopy(), metav1.UpdateOptions{})
	require.NoError(t, err, "Nodes.Update")
	curr2, err = fakeClient.KubernetesFakeClientset.CoreV1().Nodes().Update(
		ctx,
		node2.DeepCopy(), metav1.UpdateOptions{})
	require.NoError(t, err, "Nodes.Update")

	// check all events
	expectUpsert(t, events, normalCompare, "update1")
	expectUpsert(t, events, normalCompare, "update1")

	expectUpsert(t, filteredEvents, filteredCompare, "update1")
	// filtered events shouldn't contain additional event
	expectNoEvent(t, filteredEvents, 100*time.Millisecond)

	// Test that multiple events for the same key are coalesced.
	// We'll use another subscriber to validate that all the changes
	// have been processed by the resource.
	{
		ctx2, cancel2 := context.WithCancel(ctx)
		events2 := nodes.Events(ctx2)

		expectUpsert(t, events2, normalCompare, "update1")
		expectUpsert(t, events2, normalCompare, "update1")

		expectSync(t, events2)

		for i := 2; i <= 10; i++ {
			update := corev1.NodePhase(fmt.Sprintf("update%d", i))
			node.Status.Phase = update
			node.ObjectMeta.Generation = int64(i)
			node.ObjectMeta.ResourceVersion = curr.ResourceVersion

			node2.Status.Phase = update
			node2.ObjectMeta.Generation = int64(i)
			node2.ObjectMeta.ResourceVersion = curr2.ResourceVersion

			curr2, err = fakeClient.KubernetesFakeClientset.CoreV1().Nodes().Update(
				ctx,
				node2.DeepCopy(), metav1.UpdateOptions{})
			require.NoError(t, err, "Nodes.Update")

			curr, err = fakeClient.KubernetesFakeClientset.CoreV1().Nodes().Update(
				ctx,
				node.DeepCopy(), metav1.UpdateOptions{})
			require.NoError(t, err, "Nodes.Update")

			expectUpsert(t, events2, normalCompare, update)
			expectUpsert(t, events2, normalCompare, update)

		}
		cancel2()
		for range events2 {
		}
	}

	// We should now see either just the last change, or one intermediate change
	// and the last change. Iterate until both nodes are observed with the final generation.
	pending := map[string]struct{}{
		nodeName:       {},
		"another-node": {},
	}
	for len(pending) > 0 {
		ev := getEvent(t, events)
		require.Equal(t, resource.Upsert, ev.Kind)
		require.True(t, normalCompare(ev.Key.Name))
		if ev.Object.Generation == node.ObjectMeta.Generation {
			delete(pending, ev.Key.Name)
		}
		ev.Done(nil)
	}

	// for filtered resource, we only expect nodeName
	ev := getEvent(t, filteredEvents)
	require.Equal(t, resource.Upsert, ev.Kind)
	require.Equal(t, nodeName, ev.Key.Name)
	ev.Done(nil)
	if ev.Object.Generation != node.ObjectMeta.Generation {
		ev := getEvent(t, filteredEvents)
		require.Equal(t, resource.Upsert, ev.Kind)
		require.Equal(t, nodeName, ev.Key.Name)
		require.Equal(t, node.ObjectMeta.Generation, ev.Object.Generation)
		ev.Done(nil)
	}

	// Finally delete the node
	fakeClient.KubernetesFakeClientset.CoreV1().Nodes().Delete(
		ctx,
		node.Name,
		metav1.DeleteOptions{})
	fakeClient.KubernetesFakeClientset.CoreV1().Nodes().Delete(
		ctx,
		node2.Name,
		metav1.DeleteOptions{})

	expectDelete(t, events, nodeName)
	expectDelete(t, events, "another-node")
	expectDelete(t, filteredEvents, nodeName)

	// Cancel the subscriber context and verify that the stream gets completed.
	cancel()

	// No more events should be observed.
	ev, ok := <-events
	if ok {
		t.Fatalf("unexpected event still in stream: %v", ev)
	}

	ev, ok = <-filteredEvents
	if ok {
		t.Fatalf("unexpected event still in stream: %v", ev)
	}

	// Finally check that the hive stops correctly. Note that we're not doing this in a
	// defer to avoid potentially deadlocking on the Fatal calls.
	if err := hive.Stop(tlog, context.TODO()); err != nil {
		t.Fatalf("hive.Stop failed: %s", err)
	}
}

func TestFilteredResource_ProcessingFailure(t *testing.T) {
	var (
		nodeName = "some-node"
		node     = &corev1.Node{
			ObjectMeta: metav1.ObjectMeta{
				Name:       nodeName,
				Generation: 0,
			},
			Status: corev1.NodeStatus{
				Phase: "init",
			},
		}
		node2 = &corev1.Node{
			ObjectMeta: metav1.ObjectMeta{
				Name:       "another-node",
				Generation: 0,
			},
			Status: corev1.NodeStatus{
				Phase: "init",
			},
		}

		lw = createsAndDeletesListerWatcher{events: make(chan watch.Event, 100)}

		nodes         resource.Resource[*corev1.Node]
		filteredNodes resource.FilteredResource[*corev1.Node]

		events         <-chan resource.Event[*corev1.Node]
		filteredEvents <-chan resource.Event[*corev1.Node]
	)

	ctx, cancel := context.WithTimeout(t.Context(), testTimeout)
	defer cancel()

	hive := hive.New(
		cell.Provide(
			func(lc cell.Lifecycle, mp workqueue.MetricsProvider) resource.Resource[*corev1.Node] {
				return resource.New[*corev1.Node](lc, &lw, nil)
			}),
		nodesFilteredResource,
		cell.Invoke(func(r resource.Resource[*corev1.Node]) {
			nodes = r
			events = nodes.Events(ctx)
		}),
		cell.Invoke(func(r resource.FilteredResource[*corev1.Node]) {
			filteredNodes = r
			filteredEvents = filteredNodes.Events(ctx)
		}))

	tlog := hivetest.Logger(t)
	if err := hive.Start(tlog, ctx); err != nil {
		t.Fatalf("hive.Start failed: %s", err)
	}

	expectSync(t, events)
	expectSync(t, filteredEvents)

	normalCompare := func(nn string) bool { return nn == "another-node" || nn == nodeName }
	filteredCompare := func(nn string) bool { return nn == nodeName }

	lw.events <- watch.Event{
		Type:   watch.Added,
		Object: node.DeepCopy(),
	}
	lw.events <- watch.Event{
		Type:   watch.Added,
		Object: node2.DeepCopy(),
	}

	expectUpsert(t, events, normalCompare, node.Status.Phase)
	expectUpsert(t, events, normalCompare, node.Status.Phase)

	{ // failure in filtered resource
		ev := getEvent(t, filteredEvents)
		require.Equal(t, resource.Upsert, ev.Kind)
		ev.Done(errors.New("filtered upsert error"))

		expectUpsert(t, filteredEvents, filteredCompare, node.Status.Phase) // retry
		expectNoEvent(t, events, 100*time.Millisecond)
	}

	node.Status.Phase = "update1"
	node.ObjectMeta.ResourceVersion = "2"

	node2.Status.Phase = "update1"
	node2.ObjectMeta.ResourceVersion = "2"

	lw.events <- watch.Event{
		Type:   watch.Modified,
		Object: node.DeepCopy(),
	}
	lw.events <- watch.Event{
		Type:   watch.Modified,
		Object: node2.DeepCopy(),
	}

	// failure in normal resource
	for range 2 {
		ev := getEvent(t, events)
		require.Equal(t, resource.Upsert, ev.Kind)
		if ev.Key.Name == nodeName {
			require.Equal(t, node.Status.Phase, ev.Object.Status.Phase)
			ev.Done(errors.New("normal upsert error"))
		} else {
			require.Equal(t, node2.Name, ev.Key.Name)
			require.Equal(t, node2.Status.Phase, ev.Object.Status.Phase)
			ev.Done(nil)
		}
	}

	expectUpsert(t, filteredEvents, filteredCompare, "update1")
	// filtered events shouldn't contain additional event
	expectNoEvent(t, filteredEvents, 100*time.Millisecond)

	cancel()

	ev, ok := <-events
	if ok {
		t.Fatalf("unexpected event still in stream: %v", ev)
	}

	ev, ok = <-filteredEvents
	if ok {
		t.Fatalf("unexpected event still in stream: %v", ev)
	}

	require.NoError(t, hive.Stop(tlog, context.TODO()))
}

func getEvent[T k8sRuntime.Object](t *testing.T, evs <-chan resource.Event[T]) resource.Event[T] {
	t.Helper()
	ev, ok := <-evs
	require.True(t, ok, "events channel closed unexpectedly")
	return ev
}

func expectUpsert(t *testing.T, evs <-chan resource.Event[*corev1.Node], comp func(string) bool, phase corev1.NodePhase) {
	t.Helper()
	ev := getEvent(t, evs)
	require.Equal(t, resource.Upsert, ev.Kind)
	require.True(t, comp(ev.Key.Name), "unexpected node name %s", ev.Key.Name)
	if phase != "" {
		require.Equal(t, phase, ev.Object.Status.Phase)
	}
	ev.Done(nil)
}

func expectSync(t *testing.T, evs <-chan resource.Event[*corev1.Node]) {
	t.Helper()
	ev := getEvent(t, evs)
	require.Equal(t, resource.Sync, ev.Kind)
	require.Nil(t, ev.Object)
	ev.Done(nil)
}

func expectDelete(t *testing.T, evs <-chan resource.Event[*corev1.Node], name string) {
	t.Helper()
	ev := getEvent(t, evs)
	require.Equal(t, resource.Delete, ev.Kind)
	require.Equal(t, name, ev.Key.Name)
	ev.Done(nil)
}

func expectNoEvent(t *testing.T, evs <-chan resource.Event[*corev1.Node], timeout time.Duration) {
	t.Helper()
	select {
	case ev, ok := <-evs:
		if ok {
			require.Fail(t, "unexpected event", "%v", ev)
		}
	case <-time.After(timeout):
		// expected
	}
}
