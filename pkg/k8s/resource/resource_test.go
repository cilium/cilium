// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package resource_test

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"go.uber.org/goleak"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8sRuntime "k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/watch"
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
	goleak.VerifyTestMain(m, goleak.Cleanup(cleanup))
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
	ev := <-events
	assert.Equal(t, resource.Upsert, ev.Kind)
	assert.Equal(t, ev.Key.Name, nodeName)
	assert.Equal(t, ev.Object.GetName(), node.Name)
	assert.Equal(t, ev.Object.Status.Phase, node.Status.Phase)
	ev.Done(nil)

	// Second should be a sync.
	//
	// We work around the rare race condition in which we see the same
	// upsert event twice due to it being inserted into store but our
	// Add handler finishes after the initial listing has been processed (#23079).
	// Proper fix is to make sure updates to store happen synchronously with queueing
	// and subscribing.
	ev = <-events
	if ev.Kind == resource.Upsert {
		ev = <-events
	}
	assert.Equal(t, resource.Sync, ev.Kind)
	assert.Nil(t, ev.Object)
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

	ev = <-events
	assert.Equal(t, resource.Upsert, ev.Kind)
	assert.Equal(t, ev.Key.Name, nodeName)
	assert.Equal(t, ev.Object.Status.Phase, corev1.NodePhase("update1"))
	ev.Done(nil)

	// Test that multiple events for the same key are coalesced.
	// We'll use another subscriber to validate that all the changes
	// have been processed by the resource.
	// This also verifies that late subscribers correctly receive the
	// sync event.
	{
		ctx2, cancel2 := context.WithCancel(ctx)
		events2 := nodes.Events(ctx2)

		ev2 := <-events2
		assert.Equal(t, resource.Upsert, ev2.Kind)
		ev2.Done(nil)

		ev2 = <-events2
		assert.Equal(t, resource.Sync, ev2.Kind)
		ev2.Done(nil)

		for i := 2; i <= 10; i++ {
			version := fmt.Sprintf("%d", i)
			node.Status.Phase = corev1.NodePhase(fmt.Sprintf("update%d", i))
			node.ObjectMeta.ResourceVersion = version
			fakeClient.KubernetesFakeClientset.Tracker().Update(
				corev1.SchemeGroupVersion.WithResource("nodes"),
				node.DeepCopy(), "")
			ev2 := <-events2
			assert.Equal(t, resource.Upsert, ev2.Kind)
			assert.Equal(t, version, ev2.Object.ResourceVersion)
			ev2.Done(nil)
		}
		cancel2()
		for range events2 {
		}
	}

	// We should now see either just the last change, or one intermediate change
	// and the last change.
	ev = <-events
	assert.Equal(t, resource.Upsert, ev.Kind)
	assert.Equal(t, nodeName, ev.Key.Name)
	ev.Done(nil)
	if ev.Object.ResourceVersion != node.ObjectMeta.ResourceVersion {
		ev = <-events
		assert.Equal(t, resource.Upsert, ev.Kind)
		assert.Equal(t, nodeName, ev.Key.Name)
		assert.Equal(t, node.ObjectMeta.ResourceVersion, ev.Object.ResourceVersion)
		ev.Done(nil)
	}

	// Finally delete the node
	fakeClient.KubernetesFakeClientset.Tracker().Delete(
		corev1.SchemeGroupVersion.WithResource("nodes"),
		"", "some-node")

	ev = <-events
	assert.Equal(t, resource.Delete, ev.Kind)
	assert.Equal(t, nodeName, ev.Key.Name)
	assert.Equal(t, node.ObjectMeta.ResourceVersion, ev.Object.ResourceVersion)
	ev.Done(nil)

	// Cancel the subscriber context and verify that the stream gets completed.
	cancel()

	// No more events should be observed.
	ev, ok := <-events
	if ok {
		t.Fatalf("unexpected event still in stream: %v", ev)
	}

	// Finally check that the hive stops correctly. Note that we're not doing this in a
	// defer to avoid potentially deadlocking on the Fatal calls.
	if err := hive.Stop(context.TODO()); err != nil {
		t.Fatalf("hive.Stop failed: %s", err)
	}
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

	rateLimiterUsed := counter{}
	rateLimiter := func() workqueue.RateLimiter {
		rateLimiterUsed.Inc()
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
		assert.Equal(t, int64(1), rateLimiterUsed.Get())
		ev.Done(nil)
		cancel()
		_, ok := <-events
		assert.False(t, ok)
	}

	// Test that sync events are retried
	{
		xs := nodes.Events(ctx, resource.WithErrorHandler(RetryFiveTimes))

		expectedErr := errors.New("sync")
		numRetries := counter{}

		for ev := range xs {
			switch ev.Kind {
			case resource.Sync:
				numRetries.Inc()
				ev.Done(expectedErr)
			case resource.Upsert:
				ev.Done(nil)
			case resource.Delete:
				t.Fatalf("unexpected delete of %s", ev.Key)
			}
		}

		assert.Equal(t, int64(5), numRetries.Get(), "expected to see 5 retries for sync")
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
		numRetries := counter{}

		for ev := range xs {
			switch ev.Kind {
			case resource.Sync:
				ev.Done(nil)
			case resource.Upsert:
				numRetries.Inc()
				ev.Done(expectedErr)
			case resource.Delete:
				t.Fatalf("unexpected delete of %s", ev.Key)
			}
		}

		assert.Equal(t, int64(5), numRetries.Get(), "expected to see 5 retries for update")
	}

	// Test that delete events are retried
	{
		xs := nodes.Events(ctx, resource.WithErrorHandler(RetryFiveTimes))

		expectedErr := errors.New("delete")
		numRetries := counter{}

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
				numRetries.Inc()
				ev.Done(expectedErr)
			}
		}

		assert.Equal(t, int64(5), numRetries.Get(), "expected to see 5 retries for delete")
	}

	err = hive.Stop(ctx)
	assert.NoError(t, err)
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

type counter struct{ int64 }

func (c *counter) Inc() {
	atomic.AddInt64(&c.int64, 1)
}

func (c *counter) Get() int64 {
	return atomic.LoadInt64(&c.int64)
}
