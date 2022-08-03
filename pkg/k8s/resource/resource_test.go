// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package resource

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/spf13/pflag"
	"github.com/spf13/viper"
	"go.uber.org/fx"
	"go.uber.org/fx/fxtest"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"

	"github.com/cilium/cilium/pkg/hive"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/utils"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/stream"
)

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
	var node = &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name:            "some-node",
			ResourceVersion: "0",
		},
		Status: corev1.NodeStatus{
			Phase: "init",
		},
	}

	runTestWithNodesResource(t, func(app *fxtest.App, res Resource[*corev1.Node], cs *k8sClient.FakeClientset) {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()

		// Create the initial version of the node.
		cs.KubernetesFakeClientset.Tracker().Create(
			corev1.SchemeGroupVersion.WithResource("nodes"),
			node, "")

		errs := make(chan error, 1)
		xs := stream.ToChannel[Event[*corev1.Node]](ctx, errs, res)

		app.RequireStart()

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
		store, err := res.Store(ctx)
		if err != nil {
			t.Fatalf("expected non-nil error from Store(), got: %q", err)
		}
		testStore(t, node, store)

		// Update the node and check the update event
		node.Status.Phase = "update1"
		node.ObjectMeta.ResourceVersion = "1"
		cs.KubernetesFakeClientset.Tracker().Update(
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
		cs.KubernetesFakeClientset.Tracker().Delete(
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

		// Finally check that the app stops correctly. Note that we're not doing this in a
		// defer to avoid potentially deadlocking on the Fatal calls.
		app.RequireStop()
	})
}

func TestResourceCompletionOnStop(t *testing.T) {
	runTestWithNodesResource(t, func(app *fxtest.App, res Resource[*corev1.Node], cs *k8sClient.FakeClientset) {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()

		errs := make(chan error, 1)
		xs := stream.ToChannel[Event[*corev1.Node]](ctx, errs, res)

		app.RequireStart()

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
		store, err := res.Store(ctx)
		if err != nil {
			t.Fatalf("expected non-nil error from Store(), got %q", err)
		}
		if len(store.List()) != 0 {
			t.Fatalf("expected empty store, got %d items", len(store.List()))
		}

		// Stop the application to stop the resource.
		app.RequireStop()

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

	})
}

func TestResourceSyncEventRetry(t *testing.T) {
	runTestWithNodesResource(t, func(app *fxtest.App, res Resource[*corev1.Node], cs *k8sClient.FakeClientset) {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()

		errs := make(chan error, 1)
		xs := stream.ToChannel[Event[*corev1.Node]](ctx, errs, res)

		app.RequireStart()

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

		app.RequireStop()

		if numRetries.Get() != defaultMaxRetries {
			t.Fatalf("expected to see %d retry attempts, saw %d", defaultMaxRetries, numRetries)
		}

		err := <-errs
		if err != expectedErr {
			t.Fatalf("expected %q error, got %q", expectedErr, err)
		}
	})
}

func TestResourceSyncEventRetryOnce(t *testing.T) {
	runTestWithNodesResource(t, func(app *fxtest.App, res Resource[*corev1.Node], cs *k8sClient.FakeClientset) {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()

		errs := make(chan error, 1)
		xs := stream.ToChannel[Event[*corev1.Node]](ctx, errs, res)

		app.RequireStart()

		expectedErr := errors.New("update")
		numRetries := counter{}

		for ev := range xs {
			ev.Handle(
				func(s Store[*corev1.Node]) error {
					if numRetries.Get() == 1 {
						cancel()
						return nil
					}
					numRetries.Inc()
					return expectedErr
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
		}

		app.RequireStop()

		if numRetries.Get() != 1 {
			t.Fatalf("expected to see 1 retry attempt, saw %d", numRetries)
		}

		err := <-errs
		if err != nil {
			t.Fatalf("expected nil error, got %q", err)
		}
	})
}

func TestResourceUpdateEventRetry(t *testing.T) {
	var node = &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name:            "some-node",
			ResourceVersion: "0",
		},
		Status: corev1.NodeStatus{
			Phase: "init",
		},
	}

	runTestWithNodesResource(t, func(app *fxtest.App, res Resource[*corev1.Node], cs *k8sClient.FakeClientset) {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()

		// Create the initial version of the node.
		cs.KubernetesFakeClientset.Tracker().Create(
			corev1.SchemeGroupVersion.WithResource("nodes"),
			node, "")

		errs := make(chan error, 1)
		xs := stream.ToChannel[Event[*corev1.Node]](ctx, errs, res)

		app.RequireStart()

		expectedErr := errors.New("sync")
		numRetries := counter{}

		// Since no objects were created, we'll only see a sync event.
		// Always return an error to force reprocessing until we hit the
		// retry limit.
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

		app.RequireStop()

		if numRetries.Get() != defaultMaxRetries {
			t.Fatalf("expected to see %d retry attempts, saw %d", defaultMaxRetries, numRetries)
		}

		err := <-errs
		if err != expectedErr {
			t.Fatalf("expected %q error, got %q", expectedErr, err)
		}
	})
}

//
// Helpers
//

func runTestWithNodesResource(t *testing.T, test func(app *fxtest.App, res Resource[*corev1.Node], cs *k8sClient.FakeClientset)) {
	nodesLW := func(c k8sClient.Clientset) cache.ListerWatcher {
		return utils.ListerWatcherFromTyped[*corev1.NodeList](c.CoreV1().Nodes())
	}

	var (
		res Resource[*corev1.Node]
		cs  *k8sClient.FakeClientset
	)

	// Create a test application with a fake clientset and the nodes resource,
	// and pull the objects into 'res' and 'cs'.
	testApp, err := hive.New(
		viper.New(),
		pflag.NewFlagSet("", pflag.ContinueOnError),

		k8sClient.FakeClientCell,
		hive.NewCell("test",
			fx.Provide(
				NewResourceConstructorWithRateLimiter[*corev1.Node](testRateLimiter(), nodesLW),
			),
			fx.Populate(&res, &cs),
		)).TestApp(t)

	if err != nil {
		t.Fatalf("TestApp() error: %s", err)
	}

	test(testApp, res, cs)
}

type counter struct{ int64 }

func (c *counter) Inc() {
	atomic.AddInt64(&c.int64, 1)
}

func (c *counter) Get() int64 {
	return atomic.LoadInt64(&c.int64)
}

type nopLimiter struct {
	lock.Mutex
	requeues map[any]int
}

func (n *nopLimiter) When(item any) time.Duration {
	n.Lock()
	n.requeues[item] = 0
	n.Unlock()
	return time.Duration(1)
}
func (n *nopLimiter) Forget(item any) {
	n.Lock()
	delete(n.requeues, item)
	n.Unlock()
}
func (n *nopLimiter) NumRequeues(item any) int {
	n.Lock()
	defer n.Unlock()
	return n.requeues[item]
}

// testRateLimiter is a custom rate limiter for the tests to allow testing retrying
// without making the tests slow.
func testRateLimiter() workqueue.RateLimiter {
	return &nopLimiter{requeues: make(map[any]int)}
}
