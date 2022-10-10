// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package resource

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"go.uber.org/goleak"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/util/workqueue"

	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/utils"
	"github.com/cilium/cilium/pkg/stream"
)

const testTimeout = time.Minute

func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m)
}

func testStore(t *testing.T, node *corev1.Node, store Store[*corev1.Node]) {
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
	item, exists, err = store.GetByKey(Key{Name: node.ObjectMeta.Name})
	check()
	item, exists, err = store.Get(node)
	check()

	keys := []Key{}
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

func TestResourceWithFakeClient(t *testing.T) {
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

		nodes          Resource[*corev1.Node]
		fakeClient, cs = k8sClient.NewFakeClientset()
	)

	// Create the initial version of the node. Do this before anything
	// starts watching the resources to avoid a race.
	fakeClient.KubernetesFakeClientset.Tracker().Create(
		corev1.SchemeGroupVersion.WithResource("nodes"),
		node, "")

	hive := hive.New(
		cell.Provide(func() k8sClient.Clientset { return cs }),
		nodesResource,
		cell.Invoke(func(r Resource[*corev1.Node]) {
			nodes = r
		}))

	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	if err := hive.Start(ctx); err != nil {
		t.Fatalf("hive.Start failed: %s", err)
	}

	errs := make(chan error, 1)
	xs := stream.ToChannel[Event[*corev1.Node]](ctx, errs, nodes)

	// First event should be the node (initial set)
	(<-xs).Handle(
		func(_ Store[*corev1.Node]) error {
			t.Fatal("unexpected sync")
			return nil
		},
		func(key Key, node *corev1.Node) error {
			if key.String() != "some-node" {
				t.Fatalf("unexpected update of %s", key)
			}
			if node.GetName() != "some-node" {
				t.Fatalf("unexpected node name: %#v", node)
			}
			if node.Status.Phase != "init" {
				t.Fatalf("unexpected status in node, expected \"init\", got: %s", node.Status.Phase)
			}
			return nil
		},
		func(key Key, node *corev1.Node) error {
			t.Fatalf("unexpected delete of %s", key)
			return nil
		},
	)

	// Second should be a sync.
	(<-xs).Handle(
		func(s Store[*corev1.Node]) error {
			testStore(t, node, s)
			return nil
		},
		func(key Key, node *corev1.Node) error {
			t.Fatalf("unexpected update of %s", key)
			return nil
		},
		func(key Key, node *corev1.Node) error {
			t.Fatalf("unexpected delete of %s", key)
			return nil
		},
	)

	// After sync event we can also use Store() with it blocking.
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
		node, "")
	(<-xs).Handle(
		func(_ Store[*corev1.Node]) error {
			t.Fatalf("unexpected sync")
			return nil
		},
		func(key Key, node *corev1.Node) error {
			if key.String() != "some-node" {
				t.Fatalf("unexpected update of %s", key)
			}
			if node.Status.Phase != "update1" {
				t.Fatalf("unexpected status in node, expected \"update1\", got: %s", node.Status.Phase)
			}
			return nil
		},
		func(key Key, node *corev1.Node) error {
			t.Fatalf("unexpected delete")
			return nil
		},
	)

	// Finally delete the node
	fakeClient.KubernetesFakeClientset.Tracker().Delete(
		corev1.SchemeGroupVersion.WithResource("nodes"),
		"", "some-node")
	(<-xs).Handle(
		func(_ Store[*corev1.Node]) error {
			t.Fatalf("unexpected sync")
			return nil
		},
		func(key Key, node *corev1.Node) error {
			t.Fatalf("unexpected update of %s: %s", key, node)
			return nil
		},
		func(key Key, node *corev1.Node) error {
			if key.String() != "some-node" {
				t.Fatalf("unexpected key in delete of node: %s", key)
			}
			if node.ResourceVersion != "1" {
				t.Fatalf("unexpected version at delete, expected 1, got %q", node.ResourceVersion)
			}
			return nil
		},
	)

	// Cancel the subscriber context and verify that the stream gets completed.
	cancel()

	// No more events should be observed.
	ev, ok := <-xs
	if ok {
		t.Fatalf("unexpected event still in stream: %v", ev)
	}

	// Stream should complete without errors
	err = <-errs
	if err != nil {
		t.Fatalf("expected nil error, got %s", err)
	}

	// Finally check that the hive stops correctly. Note that we're not doing this in a
	// defer to avoid potentially deadlocking on the Fatal calls.
	if err := hive.Stop(context.TODO()); err != nil {
		t.Fatalf("hive.Stop failed: %s", err)
	}
}

func TestResourceCompletionOnStop(t *testing.T) {
	var nodes Resource[*corev1.Node]

	hive := hive.New(
		k8sClient.FakeClientCell,
		nodesResource,
		cell.Invoke(func(r Resource[*corev1.Node]) {
			nodes = r
		}))

	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	if err := hive.Start(ctx); err != nil {
		t.Fatalf("hive.Start failed: %s", err)
	}

	errs := make(chan error, 1)
	xs := stream.ToChannel[Event[*corev1.Node]](ctx, errs, nodes)

	// We should only see a sync event
	(<-xs).Handle(
		func(s Store[*corev1.Node]) error {
			return nil
		},
		func(key Key, node *corev1.Node) error {
			t.Fatalf("unexpected update of %s", key)
			return nil
		},
		func(key Key, node *corev1.Node) error {
			t.Fatalf("unexpected delete of %s", key)
			return nil
		},
	)

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

	// No event should be observed.
	ev, ok := <-xs
	if ok {
		t.Fatalf("unexpected event still in stream: %v", ev)
	}

	// Stream should complete without errors
	err = <-errs
	if err != nil {
		t.Fatalf("expected nil error, got %s", err)
	}
}

var RetryFiveTimes ErrorHandler = func(key Key, numRetries int, err error) ErrorAction {
	if numRetries >= 4 {
		return ErrorActionStop
	}
	return ErrorActionRetry
}

func TestResourceRetries(t *testing.T) {
	var (
		nodes          Resource[*corev1.Node]
		fakeClient, cs = k8sClient.NewFakeClientset()
	)

	rateLimiterUsed := counter{}
	rateLimiter := func() workqueue.RateLimiter {
		rateLimiterUsed.Inc()
		return workqueue.DefaultControllerRateLimiter()
	}

	hive := hive.New(
		cell.Provide(func() k8sClient.Clientset { return cs }),
		cell.Provide(func(lc hive.Lifecycle, c k8sClient.Clientset) Resource[*corev1.Node] {
			nodesLW := utils.ListerWatcherFromTyped[*corev1.NodeList](c.CoreV1().Nodes())
			return New[*corev1.Node](lc, nodesLW,
				WithRateLimiter(rateLimiter),
				WithErrorHandler(RetryFiveTimes))
		}),
		cell.Invoke(func(r Resource[*corev1.Node]) {
			nodes = r
		}))

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	err := hive.Start(ctx)
	assert.NoError(t, err)

	// Check that the WithRateLimiter option works.
	ev, err := stream.First[Event[*corev1.Node]](ctx, nodes)
	assert.NoError(t, err)
	assert.Equal(t, int64(1), rateLimiterUsed.Get())
	ev.Done(nil)

	// Test that stream completes on a single sync error.
	{
		errs := make(chan error, 1)
		xs := stream.ToChannel[Event[*corev1.Node]](ctx, errs, nodes)

		expectedErr := errors.New("sync")
		numRetries := counter{}

		for ev := range xs {
			ev.Handle(
				func(s Store[*corev1.Node]) error {
					numRetries.Inc()
					return expectedErr
				},
				func(key Key, node *corev1.Node) error {
					return nil
				},
				func(key Key, node *corev1.Node) error {
					t.Fatalf("unexpected delete of %s", key)
					return nil
				},
			)
		}

		assert.Equal(t, int64(1), numRetries.Get(), "expected to see 1 attempt for sync")
		err = <-errs
		assert.ErrorIs(t, err, expectedErr)
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
		errs := make(chan error, 1)
		xs := stream.ToChannel[Event[*corev1.Node]](ctx, errs, nodes)

		expectedErr := errors.New("update")
		numRetries := counter{}

		for ev := range xs {
			ev.Handle(
				func(s Store[*corev1.Node]) error {
					return nil
				},
				func(key Key, node *corev1.Node) error {
					numRetries.Inc()
					return expectedErr
				},
				func(key Key, node *corev1.Node) error {
					t.Fatalf("unexpected delete of %s", key)
					return nil
				},
			)
		}

		assert.Equal(t, int64(5), numRetries.Get(), "expected to see 5 retries for update")
		err = <-errs
		assert.ErrorIs(t, err, expectedErr)
	}

	// Test that delete events are retried
	{
		errs := make(chan error, 1)
		xs := stream.ToChannel[Event[*corev1.Node]](ctx, errs, nodes)

		expectedErr := errors.New("delete")
		numRetries := counter{}

		for ev := range xs {
			ev.Handle(
				func(s Store[*corev1.Node]) error {
					return nil
				},
				func(key Key, node *corev1.Node) error {
					fakeClient.KubernetesFakeClientset.Tracker().Delete(
						corev1.SchemeGroupVersion.WithResource("nodes"),
						"", node.Name)
					return nil
				},
				func(key Key, node *corev1.Node) error {
					numRetries.Inc()
					return expectedErr
				},
			)
		}

		assert.Equal(t, int64(5), numRetries.Get(), "expected to see 5 retries for delete")
		err = <-errs
		assert.ErrorIs(t, err, expectedErr)
	}

	err = hive.Stop(ctx)
	assert.NoError(t, err)
}

//
// Helpers
//

var nodesResource = cell.Provide(
	func(lc hive.Lifecycle, c k8sClient.Clientset) Resource[*corev1.Node] {
		lw := utils.ListerWatcherFromTyped[*corev1.NodeList](c.CoreV1().Nodes())
		return New[*corev1.Node](lc, lw)
	},
)

type counter struct{ int64 }

func (c *counter) Inc() {
	atomic.AddInt64(&c.int64, 1)
}

func (c *counter) Get() int64 {
	return atomic.LoadInt64(&c.int64)
}
