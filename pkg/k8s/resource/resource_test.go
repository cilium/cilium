// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package resource_test

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"runtime"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/goleak"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8sRuntime "k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"

	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/k8s/utils"
)

const testTimeout = time.Minute

func TestMain(m *testing.M) {
	cleanup := func(exitCode int) {
		// Force garbage-collection to force finalizers to run and catch
		// missing Event.Done() calls.
		runtime.GC()
	}
	goleak.VerifyTestMain(m,
		goleak.Cleanup(cleanup),
		// Delaying workqueues used by resource.Resource[T].Events leaks this waitingLoop goroutine.
		// It does stop when shutting down but is not guaranteed to before we actually exit.
		goleak.IgnoreTopFunction("k8s.io/client-go/util/workqueue.(*delayingType).waitingLoop"),
	)
}

func testStore(t *testing.T, node *corev1.Node, store resource.Store[*corev1.Node]) {
	var (
		item   *corev1.Node
		exists bool
		err    error
	)

	check := func() {
		if err != nil {
			t.Fatalf("unexpected error from GetByKey: %s", err)
		}
		if !exists {
			t.Fatalf("GetByKey returned exists=false")
		}
		if item.Name != node.ObjectMeta.Name {
			t.Fatalf("expected item returned by GetByKey to have name %s, got %s",
				node.ObjectMeta.Name, item.ObjectMeta.Name)
		}
	}
	item, exists, err = store.GetByKey(resource.Key{Name: node.ObjectMeta.Name})
	check()
	item, exists, err = store.Get(node)
	check()

	keys := []resource.Key{}
	iter := store.IterKeys()
	for iter.Next() {
		keys = append(keys, iter.Key())
	}

	if len(keys) != 1 && keys[0].Name != "some-node" {
		t.Fatalf("unexpected keys: %#v", keys)
	}

	items := store.List()
	if len(items) != 1 && items[0].ObjectMeta.Name != "some-node" {
		t.Fatalf("unexpected items: %#v", items)
	}
}

func TestResource_WithFakeClient(t *testing.T) {
	var (
		nodeName = "some-node"
		node     = &corev1.Node{
			ObjectMeta: metav1.ObjectMeta{
				Name:            nodeName,
				ResourceVersion: "0",
			},
			Status: corev1.NodeStatus{
				Phase: "init",
			},
		}

		nodes          resource.Resource[*corev1.Node]
		fakeClient, cs = k8sClient.NewFakeClientset()

		events <-chan resource.Event[*corev1.Node]
	)

	// Create the initial version of the node. Do this before anything
	// starts watching the resources to avoid a race.
	fakeClient.KubernetesFakeClientset.Tracker().Create(
		corev1.SchemeGroupVersion.WithResource("nodes"),
		node.DeepCopy(), "")

	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	hive := hive.New(
		cell.Provide(func() k8sClient.Clientset { return cs }),
		nodesResource,
		cell.Invoke(func(r resource.Resource[*corev1.Node]) {
			nodes = r

			// Subscribe prior to starting as it's allowed. Sync event
			// for early subscribers will be emitted when informer has
			// synchronized.
			events = nodes.Events(ctx)
		}))

	if err := hive.Start(ctx); err != nil {
		t.Fatalf("hive.Start failed: %s", err)
	}

	// First event should be the node (initial set)
	ev, ok := <-events
	require.True(t, ok)
	require.Equal(t, resource.Upsert, ev.Kind)
	require.Equal(t, ev.Key.Name, nodeName)
	require.Equal(t, ev.Object.GetName(), node.Name)
	require.Equal(t, ev.Object.Status.Phase, node.Status.Phase)
	ev.Done(nil)

	// Second should be a sync.
	ev, ok = <-events
	require.True(t, ok, "events channel closed unexpectedly")
	require.Equal(t, resource.Sync, ev.Kind)
	require.Nil(t, ev.Object)
	ev.Done(nil)

	// After sync event we can also use Store() without it blocking.
	store, err := nodes.Store(ctx)
	if err != nil {
		t.Fatalf("expected non-nil error from Store(), got: %q", err)
	}
	testStore(t, node, store)

	// Update the node and check the update event
	node.Status.Phase = "update1"
	node.ObjectMeta.ResourceVersion = "1"
	fakeClient.KubernetesFakeClientset.Tracker().Update(
		corev1.SchemeGroupVersion.WithResource("nodes"),
		node.DeepCopy(), "")

	ev, ok = <-events
	require.True(t, ok, "events channel closed unexpectedly")
	require.Equal(t, resource.Upsert, ev.Kind)
	require.Equal(t, ev.Key.Name, nodeName)
	require.Equal(t, ev.Object.Status.Phase, corev1.NodePhase("update1"))
	ev.Done(nil)

	// Test that multiple events for the same key are coalesced.
	// We'll use another subscriber to validate that all the changes
	// have been processed by the resource.
	// This also verifies that late subscribers correctly receive the
	// sync event.
	{
		ctx2, cancel2 := context.WithCancel(ctx)
		events2 := nodes.Events(ctx2)

		ev2, ok := <-events2
		require.True(t, ok, "events channel closed unexpectedly")
		require.Equal(t, resource.Upsert, ev2.Kind)
		ev2.Done(nil)

		ev2, ok = <-events2
		require.True(t, ok, "events channel closed unexpectedly")
		require.Equal(t, resource.Sync, ev2.Kind)
		ev2.Done(nil)

		for i := 2; i <= 10; i++ {
			version := fmt.Sprintf("%d", i)
			node.Status.Phase = corev1.NodePhase(fmt.Sprintf("update%d", i))
			node.ObjectMeta.ResourceVersion = version
			fakeClient.KubernetesFakeClientset.Tracker().Update(
				corev1.SchemeGroupVersion.WithResource("nodes"),
				node.DeepCopy(), "")
			ev2, ok := <-events2
			require.True(t, ok, "events channel closed unexpectedly")
			require.Equal(t, resource.Upsert, ev2.Kind)
			require.Equal(t, version, ev2.Object.ResourceVersion)
			ev2.Done(nil)
		}
		cancel2()
		for range events2 {
		}
	}

	// We should now see either just the last change, or one intermediate change
	// and the last change.
	ev, ok = <-events
	require.True(t, ok, "events channel closed unexpectedly")
	require.Equal(t, resource.Upsert, ev.Kind)
	require.Equal(t, nodeName, ev.Key.Name)
	ev.Done(nil)
	if ev.Object.ResourceVersion != node.ObjectMeta.ResourceVersion {
		ev, ok = <-events
		require.True(t, ok, "events channel closed unexpectedly")
		require.Equal(t, resource.Upsert, ev.Kind)
		require.Equal(t, nodeName, ev.Key.Name)
		require.Equal(t, node.ObjectMeta.ResourceVersion, ev.Object.ResourceVersion)
		ev.Done(nil)
	}

	// Finally delete the node
	fakeClient.KubernetesFakeClientset.Tracker().Delete(
		corev1.SchemeGroupVersion.WithResource("nodes"),
		"", "some-node")

	ev, ok = <-events
	require.True(t, ok, "events channel closed unexpectedly")
	require.Equal(t, resource.Delete, ev.Kind)
	require.Equal(t, nodeName, ev.Key.Name)
	require.Equal(t, node.ObjectMeta.ResourceVersion, ev.Object.ResourceVersion)
	ev.Done(nil)

	// Cancel the subscriber context and verify that the stream gets completed.
	cancel()

	// No more events should be observed.
	ev, ok = <-events
	if ok {
		t.Fatalf("unexpected event still in stream: %v", ev)
	}

	// Finally check that the hive stops correctly. Note that we're not doing this in a
	// defer to avoid potentially deadlocking on the Fatal calls.
	if err := hive.Stop(context.TODO()); err != nil {
		t.Fatalf("hive.Stop failed: %s", err)
	}
}

type createsAndDeletesListerWatcher struct {
	events chan watch.Event
}

func (lw *createsAndDeletesListerWatcher) ResultChan() <-chan watch.Event {
	return lw.events
}

func (lw *createsAndDeletesListerWatcher) Stop() {
	close(lw.events)
}

func (*createsAndDeletesListerWatcher) List(options metav1.ListOptions) (k8sRuntime.Object, error) {
	return &corev1.NodeList{}, nil
}

func (lw *createsAndDeletesListerWatcher) Watch(options metav1.ListOptions) (watch.Interface, error) {
	return lw, nil
}

var _ cache.ListerWatcher = &createsAndDeletesListerWatcher{}
var _ watch.Interface = &createsAndDeletesListerWatcher{}

func TestResource_RepeatedDelete(t *testing.T) {
	var (
		nodeName = "some-node"
		node     = &corev1.Node{
			ObjectMeta: metav1.ObjectMeta{
				Name:            nodeName,
				ResourceVersion: "0",
			},
			Status: corev1.NodeStatus{
				Phase: "init",
			},
		}

		nodes resource.Resource[*corev1.Node]

		lw     = createsAndDeletesListerWatcher{events: make(chan watch.Event, 100)}
		events <-chan resource.Event[*corev1.Node]
	)

	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	hive := hive.New(
		cell.Provide(
			func(lc hive.Lifecycle) resource.Resource[*corev1.Node] {
				return resource.New[*corev1.Node](lc, &lw)
			}),

		cell.Invoke(func(r resource.Resource[*corev1.Node]) {
			nodes = r

			// Subscribe prior to starting as it's allowed. Sync event
			// for early subscribers will be emitted when informer has
			// synchronized.
			events = nodes.Events(ctx)
		}))

	if err := hive.Start(ctx); err != nil {
		t.Fatalf("hive.Start failed: %s", err)
	}

	ev, ok := <-events
	require.True(t, ok, "events channel closed unexpectedly")
	require.Equal(t, resource.Sync, ev.Kind)
	require.Nil(t, ev.Object)
	ev.Done(nil)

	finalVersion := "99999"

	// Repeatedly create and delete the node in the background
	// while "unreliably" processing some of the delete events.
	go func() {
		for i := 0; i < 1000; i++ {
			node.ObjectMeta.ResourceVersion = fmt.Sprintf("%d", i)

			lw.events <- watch.Event{
				Type:   watch.Added,
				Object: node.DeepCopy(),
			}

			// Sleep tiny amount to force a context switch
			time.Sleep(time.Microsecond)

			lw.events <- watch.Event{
				Type:   watch.Deleted,
				Object: node.DeepCopy(),
			}

			// Sleep tiny amount to force a context switch
			time.Sleep(time.Microsecond)
		}

		// Create final copy of the object to mark the end of the test.
		node.ObjectMeta.ResourceVersion = finalVersion
		lw.events <- watch.Event{
			Type:   watch.Added,
			Object: node.DeepCopy(),
		}
	}()

	var (
		lastDeleteVersion uint64
		lastUpsertVersion uint64
	)
	exists := false

	for ev := range events {
		if ev.Kind == resource.Delete {
			version, _ := strconv.ParseUint(ev.Object.ObjectMeta.ResourceVersion, 10, 64)

			// Objects that we've not witnessed created should not be seen deleted.
			require.True(t, exists, "delete event for object that we didn't witness being created")

			// The upserted object's version should be less or equal to the deleted object's version.
			require.Equal(t, lastUpsertVersion, version, "expected deleted object version to equal to last upserted version")

			// Check that we don't go back in time.
			require.LessOrEqual(t, lastDeleteVersion, version, "expected always increasing ResourceVersion")
			lastDeleteVersion = version

			// Fail every 3rd deletion to test retrying.
			if rand.Intn(3) == 0 {
				ev.Done(errors.New("delete failed"))
			} else {
				exists = false
				ev.Done(nil)
			}
		} else if ev.Kind == resource.Upsert {
			exists = true

			// Check that we don't go back in time
			version, _ := strconv.ParseUint(ev.Object.ObjectMeta.ResourceVersion, 10, 64)
			require.LessOrEqual(t, lastUpsertVersion, version, "expected always increasing ResourceVersion")
			lastUpsertVersion = version

			if ev.Object.ObjectMeta.ResourceVersion == finalVersion {
				cancel()
			}
			ev.Done(nil)
		}
	}

	// Finally check that the hive stops correctly. Note that we're not doing this in a
	// defer to avoid potentially deadlocking on the Fatal calls.
	require.NoError(t, hive.Stop(context.TODO()))
}

func TestResource_CompletionOnStop(t *testing.T) {
	var nodes resource.Resource[*corev1.Node]

	hive := hive.New(
		k8sClient.FakeClientCell,
		nodesResource,
		cell.Invoke(func(r resource.Resource[*corev1.Node]) {
			nodes = r
		}))

	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	if err := hive.Start(ctx); err != nil {
		t.Fatalf("hive.Start failed: %s", err)
	}

	xs := nodes.Events(ctx)

	// We should only see a sync event
	ev := <-xs
	assert.Equal(t, resource.Sync, ev.Kind)
	ev.Done(nil)

	// After sync Store() should not block and should be empty.
	store, err := nodes.Store(ctx)
	if err != nil {
		t.Fatalf("expected non-nil error from Store(), got %q", err)
	}
	if len(store.List()) != 0 {
		t.Fatalf("expected empty store, got %d items", len(store.List()))
	}

	// Stop the hive to stop the resource.
	if err := hive.Stop(ctx); err != nil {
		t.Fatalf("hive.Stop failed: %s", err)
	}

	// No more events should be observed.
	ev, ok := <-xs
	if ok {
		t.Fatalf("unexpected event still in channel: %v", ev)
	}
}

func TestResource_WithTransform(t *testing.T) {
	type StrippedNode = metav1.PartialObjectMetadata
	var strippedNodes resource.Resource[*StrippedNode]
	var fakeClient, cs = k8sClient.NewFakeClientset()

	node := &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name:            "node",
			ResourceVersion: "0",
		},
		Status: corev1.NodeStatus{
			Phase: "init",
		},
	}

	strip := func(obj *corev1.Node) (*StrippedNode, error) {
		return &StrippedNode{TypeMeta: node.TypeMeta, ObjectMeta: node.ObjectMeta}, nil
	}

	hive := hive.New(
		cell.Provide(
			func() k8sClient.Clientset { return cs },
			func(lc hive.Lifecycle, c k8sClient.Clientset) resource.Resource[*StrippedNode] {
				lw := utils.ListerWatcherFromTyped[*corev1.NodeList](c.CoreV1().Nodes())
				return resource.New[*StrippedNode](lc, lw, resource.WithTransform(strip))
			}),

		cell.Invoke(func(r resource.Resource[*StrippedNode]) {
			strippedNodes = r
		}))

	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	if err := hive.Start(ctx); err != nil {
		t.Fatalf("hive.Start failed: %s", err)
	}

	fakeClient.KubernetesFakeClientset.Tracker().Create(
		corev1.SchemeGroupVersion.WithResource("nodes"),
		node.DeepCopy(), "")

	events := strippedNodes.Events(ctx)

	event := <-events
	assert.Equal(t, resource.Upsert, event.Kind)
	event.Done(nil)

	event = <-events
	assert.Equal(t, resource.Sync, event.Kind)
	event.Done(nil)

	// Stop the hive to stop the resource.
	if err := hive.Stop(ctx); err != nil {
		t.Fatalf("hive.Stop failed: %s", err)
	}

	// No more events should be observed.
	event, ok := <-events
	if ok {
		t.Fatalf("unexpected event still in channel: %v", event)
	}

}

func TestResource_WithoutIndexers(t *testing.T) {
	var (
		node = &corev1.Node{
			ObjectMeta: metav1.ObjectMeta{
				Name:            "test-node-1",
				ResourceVersion: "0",
			},
		}
		nodeResource   resource.Resource[*corev1.Node]
		fakeClient, cs = k8sClient.NewFakeClientset()
	)

	fakeClient.KubernetesFakeClientset.Tracker().Create(
		corev1.SchemeGroupVersion.WithResource("nodes"),
		node.DeepCopy(), "")

	hive := hive.New(
		cell.Provide(func() k8sClient.Clientset { return cs }),
		cell.Provide(
			func(lc hive.Lifecycle, cs k8sClient.Clientset) resource.Resource[*corev1.Node] {
				lw := utils.ListerWatcherFromTyped[*corev1.NodeList](cs.CoreV1().Nodes())
				return resource.New[*corev1.Node](lc, lw)
			},
		),

		cell.Invoke(func(r resource.Resource[*corev1.Node]) {
			nodeResource = r
		}),
	)

	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	if err := hive.Start(ctx); err != nil {
		t.Fatalf("hive.Start failed: %s", err)
	}

	events := nodeResource.Events(ctx)

	// wait for the upsert event
	ev, ok := <-events
	require.True(t, ok)
	require.Equal(t, resource.Upsert, ev.Kind)
	ev.Done(nil)

	// wait for the sync event
	ev, ok = <-events
	require.True(t, ok)
	assert.Equal(t, resource.Sync, ev.Kind)
	ev.Done(nil)

	// get a reference to the store
	store, err := nodeResource.Store(ctx)
	if err != nil {
		t.Fatalf("unexpected non-nil error from Store(), got: %q", err)
	}

	indexName, indexValue := "index-name", "index-value"

	// ByIndex should not find any objects
	_, err = store.ByIndex(indexName, indexValue)
	if err == nil {
		t.Fatalf("expected non-nil error from store.ByIndex(%q, %q), got nil", indexName, indexValue)
	}

	// IndexKeys should not find any keys
	_, err = store.IndexKeys(indexName, indexValue)
	if err == nil {
		t.Fatalf("unexpected non-nil error from store.IndexKeys(%q, %q), got nil", indexName, indexValue)
	}

	// Stop the hive to stop the resource.
	if err := hive.Stop(ctx); err != nil {
		t.Fatalf("hive.Stop failed: %s", err)
	}

	// No more events should be observed.
	ev, ok = <-events
	if ok {
		t.Fatalf("unexpected event still in channel: %v", ev)
	}
}

func TestResource_WithIndexers(t *testing.T) {
	var (
		nodes = [...]*corev1.Node{
			{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-node-1",
					Labels: map[string]string{
						"key": "node-1",
					},
					ResourceVersion: "0",
				},
			},
			{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-node-2",
					Labels: map[string]string{
						"key": "node-2",
					},
					ResourceVersion: "0",
				},
			},
			{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-node-3",
					Labels: map[string]string{
						"key": "node-3",
					},
					ResourceVersion: "0",
				},
			},
		}
		nodeResource   resource.Resource[*corev1.Node]
		fakeClient, cs = k8sClient.NewFakeClientset()

		indexName = "node-index-key"
		indexFunc = func(obj interface{}) ([]string, error) {
			switch t := obj.(type) {
			case *corev1.Node:
				return []string{t.Name}, nil
			}
			return nil, errors.New("object is not a *corev1.Node")
		}
	)

	for _, node := range nodes {
		fakeClient.KubernetesFakeClientset.Tracker().Create(
			corev1.SchemeGroupVersion.WithResource("nodes"),
			node.DeepCopy(), "")
	}

	hive := hive.New(
		cell.Provide(func() k8sClient.Clientset { return cs }),
		cell.Provide(
			func(lc hive.Lifecycle, cs k8sClient.Clientset) resource.Resource[*corev1.Node] {
				lw := utils.ListerWatcherFromTyped[*corev1.NodeList](cs.CoreV1().Nodes())
				return resource.New[*corev1.Node](
					lc, lw,
					resource.WithIndexers(cache.Indexers{indexName: indexFunc}),
				)
			},
		),

		cell.Invoke(func(r resource.Resource[*corev1.Node]) {
			nodeResource = r
		}),
	)

	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	if err := hive.Start(ctx); err != nil {
		t.Fatalf("hive.Start failed: %s", err)
	}

	events := nodeResource.Events(ctx)

	// wait for the upsert events
	for i := 0; i < len(nodes); i++ {
		ev, ok := <-events
		require.True(t, ok)
		require.Equal(t, resource.Upsert, ev.Kind)
		ev.Done(nil)
	}

	// wait for the sync event
	ev, ok := <-events
	require.True(t, ok)
	assert.Equal(t, resource.Sync, ev.Kind)
	ev.Done(nil)

	// get a reference to the store
	store, err := nodeResource.Store(ctx)
	if err != nil {
		t.Fatalf("unexpected non-nil error from Store(), got: %q", err)
	}

	indexValue := "test-node-2"

	// retrieve a specific node by its value for the indexer key
	found, err := store.ByIndex(indexName, indexValue)
	if err != nil {
		t.Fatalf("unexpected non-nil error from store.ByIndex(%q, %q), got: %q", indexName, indexValue, err)
	}
	require.Len(t, found, 1)
	require.Equal(t, found[0].Name, indexValue)
	require.Len(t, found[0].Labels, 1)
	require.Equal(t, found[0].Labels["key"], "node-2")

	// retrieve the keys of the stored objects whose set of indexed values includes a specific value
	keys, err := store.IndexKeys(indexName, indexValue)
	if err != nil {
		t.Fatalf("unexpected non-nil error from store.IndexKeys(%q, %q), got: %q", indexName, indexValue, err)
	}
	require.Len(t, keys, 1)
	require.Equal(t, []string{indexValue}, keys)

	// Stop the hive to stop the resource.
	if err := hive.Stop(ctx); err != nil {
		t.Fatalf("hive.Stop failed: %s", err)
	}

	// No more events should be observed.
	ev, ok = <-events
	if ok {
		t.Fatalf("unexpected event still in channel: %v", ev)
	}
}

var RetryFiveTimes resource.ErrorHandler = func(key resource.Key, numRetries int, err error) resource.ErrorAction {
	if numRetries >= 4 {
		return resource.ErrorActionStop
	}
	return resource.ErrorActionRetry
}

func TestResource_Retries(t *testing.T) {
	var (
		nodes          resource.Resource[*corev1.Node]
		fakeClient, cs = k8sClient.NewFakeClientset()
	)

	var rateLimiterUsed atomic.Int64
	rateLimiter := func() workqueue.RateLimiter {
		rateLimiterUsed.Add(1)
		return workqueue.DefaultControllerRateLimiter()
	}

	hive := hive.New(
		cell.Provide(func() k8sClient.Clientset { return cs }),
		cell.Provide(func(lc hive.Lifecycle, c k8sClient.Clientset) resource.Resource[*corev1.Node] {
			nodesLW := utils.ListerWatcherFromTyped[*corev1.NodeList](c.CoreV1().Nodes())
			return resource.New[*corev1.Node](lc, nodesLW)
		}),
		cell.Invoke(func(r resource.Resource[*corev1.Node]) {
			nodes = r
		}))

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	err := hive.Start(ctx)
	assert.NoError(t, err)

	// Check that the WithRateLimiter option works.
	{
		ctx, cancel := context.WithCancel(ctx)
		events := nodes.Events(ctx, resource.WithRateLimiter(rateLimiter()), resource.WithErrorHandler(RetryFiveTimes))
		ev := <-events
		assert.NoError(t, err)
		assert.Equal(t, int64(1), rateLimiterUsed.Load())
		ev.Done(nil)
		cancel()
		_, ok := <-events
		assert.False(t, ok)
	}

	// Test that sync events are retried
	{
		xs := nodes.Events(ctx, resource.WithErrorHandler(RetryFiveTimes))

		expectedErr := errors.New("sync")
		var numRetries atomic.Int64

		for ev := range xs {
			switch ev.Kind {
			case resource.Sync:
				numRetries.Add(1)
				ev.Done(expectedErr)
			case resource.Upsert:
				ev.Done(nil)
			case resource.Delete:
				t.Fatalf("unexpected delete of %s", ev.Key)
			}
		}

		assert.Equal(t, int64(5), numRetries.Load(), "expected to see 5 retries for sync")
	}

	var node = &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name:            "some-node",
			ResourceVersion: "0",
		},
		Status: corev1.NodeStatus{
			Phase: "init",
		},
	}

	// Create the initial version of the node.
	fakeClient.KubernetesFakeClientset.Tracker().Create(
		corev1.SchemeGroupVersion.WithResource("nodes"),
		node, "")

	// Test that update events are retried
	{
		xs := nodes.Events(ctx, resource.WithErrorHandler(RetryFiveTimes))

		expectedErr := errors.New("update")
		var numRetries atomic.Int64

		for ev := range xs {
			switch ev.Kind {
			case resource.Sync:
				ev.Done(nil)
			case resource.Upsert:
				numRetries.Add(1)
				ev.Done(expectedErr)
			case resource.Delete:
				t.Fatalf("unexpected delete of %s", ev.Key)
			}
		}

		assert.Equal(t, int64(5), numRetries.Load(), "expected to see 5 retries for update")
	}

	// Test that delete events are retried
	{
		xs := nodes.Events(ctx, resource.WithErrorHandler(RetryFiveTimes))

		expectedErr := errors.New("delete")
		var numRetries atomic.Int64

		for ev := range xs {
			switch ev.Kind {
			case resource.Sync:
				ev.Done(nil)
			case resource.Upsert:
				fakeClient.KubernetesFakeClientset.Tracker().Delete(
					corev1.SchemeGroupVersion.WithResource("nodes"),
					"", node.Name)
				ev.Done(nil)
			case resource.Delete:
				numRetries.Add(1)
				ev.Done(expectedErr)
			}
		}

		assert.Equal(t, int64(5), numRetries.Load(), "expected to see 5 retries for delete")
	}

	err = hive.Stop(ctx)
	assert.NoError(t, err)
}

func TestResource_Observe(t *testing.T) {
	var (
		nodeName = "some-node"
		node     = &corev1.Node{
			ObjectMeta: metav1.ObjectMeta{
				Name:            nodeName,
				ResourceVersion: "0",
			},
			Status: corev1.NodeStatus{
				Phase: "init",
			},
		}
		fakeClient, cs = k8sClient.NewFakeClientset()
		nodes          resource.Resource[*corev1.Node]
	)

	// Create the initial version of the node. Do this before anything
	// starts watching the resources to avoid a race.
	fakeClient.KubernetesFakeClientset.Tracker().Create(
		corev1.SchemeGroupVersion.WithResource("nodes"),
		node.DeepCopy(), "")

	hive := hive.New(
		cell.Provide(func() k8sClient.Clientset { return cs }),
		nodesResource,
		cell.Invoke(func(r resource.Resource[*corev1.Node]) {
			nodes = r
		}))

	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	if err := hive.Start(ctx); err != nil {
		t.Fatalf("hive.Start failed: %s", err)
	}

	eventWg := sync.WaitGroup{}
	completeWg := sync.WaitGroup{}

	eventWg.Add(2)    // upsert & sync
	completeWg.Add(1) // complete

	nodes.Observe(ctx, func(e resource.Event[*corev1.Node]) {
		e.Done(nil)
		eventWg.Done()
	}, func(err error) {
		completeWg.Done()
	})

	eventWg.Wait()

	// Stop the hive to stop the resource and trigger completion.
	if err := hive.Stop(ctx); err != nil {
		t.Fatalf("hive.Stop failed: %s", err)
	}
	completeWg.Wait()
}

//
// Benchmarks
//

type benchmarkListerWatcher struct {
	events chan watch.Event
}

func (lw *benchmarkListerWatcher) List(opts metav1.ListOptions) (k8sRuntime.Object, error) {
	return &corev1.NodeList{}, nil
}
func (lw *benchmarkListerWatcher) Watch(opts metav1.ListOptions) (watch.Interface, error) {
	return lw, nil
}
func (lw *benchmarkListerWatcher) Stop() {
}
func (lw *benchmarkListerWatcher) ResultChan() <-chan watch.Event {
	return lw.events
}

func BenchmarkResource(b *testing.B) {
	var (
		nodes resource.Resource[*corev1.Node]
		lw    = &benchmarkListerWatcher{
			events: make(chan watch.Event, 128),
		}
	)

	hive := hive.New(
		cell.Provide(func(lc hive.Lifecycle) resource.Resource[*corev1.Node] {
			return resource.New[*corev1.Node](lc, lw)
		}),
		cell.Invoke(func(r resource.Resource[*corev1.Node]) {
			nodes = r
		}))

	err := hive.Start(context.TODO())
	assert.NoError(b, err)

	ctx, cancel := context.WithCancel(context.Background())
	events := nodes.Events(ctx)

	ev := <-events
	assert.Equal(b, resource.Sync, ev.Kind)
	ev.Done(nil)

	b.ResetTimer()

	var wg sync.WaitGroup

	// Feed in b.N nodes as watcher events
	wg.Add(1)
	go func() {
		for i := 0; i < b.N; i++ {
			name := fmt.Sprintf("node-%d", i)
			lw.events <- watch.Event{Type: watch.Added, Object: &corev1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name: name,
					UID:  types.UID(name),
				},
			}}
		}
		wg.Done()
	}()

	// Consume the events via the resource
	for i := 0; i < b.N; i++ {
		ev, ok := <-events
		assert.True(b, ok)
		assert.Equal(b, resource.Upsert, ev.Kind)
		ev.Done(nil)
	}

	cancel()
	for ev := range events {
		ev.Done(nil)
	}

	err = hive.Stop(context.TODO())
	assert.NoError(b, err)

	wg.Wait()
}

func TestResource_SkippedDonePanics(t *testing.T) {
	t.Skip("This test can be only done manually as it tests finalizer panicing")

	var (
		node = &corev1.Node{
			ObjectMeta: metav1.ObjectMeta{
				Name:            "some-node",
				ResourceVersion: "0",
			},
			Status: corev1.NodeStatus{
				Phase: "init",
			},
		}
		nodes          resource.Resource[*corev1.Node]
		fakeClient, cs = k8sClient.NewFakeClientset()
		events         <-chan resource.Event[*corev1.Node]
	)

	// Create the initial version of the node. Do this before anything
	// starts watching the resources to avoid a race.
	fakeClient.KubernetesFakeClientset.Tracker().Create(
		corev1.SchemeGroupVersion.WithResource("nodes"),
		node.DeepCopy(), "")

	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	hive := hive.New(
		cell.Provide(func() k8sClient.Clientset { return cs }),
		nodesResource,
		cell.Invoke(func(r resource.Resource[*corev1.Node]) {
			nodes = r

			// Subscribe prior to starting as it's allowed. Sync event
			// for early subscribers will be emitted when informer has
			// synchronized.
			events = nodes.Events(ctx)
		}))

	if err := hive.Start(ctx); err != nil {
		t.Fatalf("hive.Start failed: %s", err)
	}

	// First event should be the node (initial set)
	ev := <-events
	assert.Equal(t, resource.Upsert, ev.Kind)
	// Skipping the Done() call:
	// ev.Done(nil)

	// Finalizer will now panic.
	<-events
}

//
// Helpers
//

var nodesResource = cell.Provide(
	func(lc hive.Lifecycle, c k8sClient.Clientset) resource.Resource[*corev1.Node] {
		lw := utils.ListerWatcherFromTyped[*corev1.NodeList](c.CoreV1().Nodes())
		return resource.New[*corev1.Node](lc, lw)
	},
)
