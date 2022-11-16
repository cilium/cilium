// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package resource

import (
	"context"
	"testing"
	"time"

	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	v1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	slim_fake "github.com/cilium/cilium/pkg/k8s/slim/k8s/client/clientset/versioned/fake"
	"github.com/cilium/cilium/pkg/k8s/utils"
)

type DiffStoreFixture struct {
	diffFactory  DiffStoreFactory[*v1.Service]
	observer     <-chan struct{}
	observerDone func()
	cs           *slim_fake.Clientset
	hive         *hive.Hive
}

func newDiffStoreFixture() *DiffStoreFixture {
	fixture := &DiffStoreFixture{}

	// Create a new mocked CRD client set with the pools as initial objects
	fixture.cs = slim_fake.NewSimpleClientset()

	// Construct a new Hive with mocked out dependency cells.
	fixture.hive = hive.New(
		cell.Provide(func(lc hive.Lifecycle, c k8sClient.Clientset) Resource[*v1.Service] {
			return New[*v1.Service](
				lc, utils.ListerWatcherFromTyped[*v1.ServiceList](
					c.Slim().CoreV1().Services(""),
				),
			)
		}),

		// Provide the mocked client cells directly
		cell.Provide(func() k8sClient.Clientset {
			return &k8sClient.FakeClientset{
				SlimFakeClientset: fixture.cs,
			}
		}),

		cell.Invoke(func(
			diffFactory DiffStoreFactory[*v1.Service],
		) {
			fixture.diffFactory = diffFactory
			fixture.observer, fixture.observerDone = diffFactory.Observe()
		}),

		cell.Provide(NewDiffStoreFactory[*v1.Service]),
	)

	return fixture
}

// Test that adding and deleting objects trigger signals
func TestDiffSignal(t *testing.T) {
	fixture := newDiffStoreFixture()
	tracker := fixture.cs.Tracker()

	// Add an initial object.
	err := tracker.Add(&v1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name: "svc-a",
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	err = fixture.hive.Start(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	diffstore := fixture.diffFactory.NewStore()

	timer := time.NewTimer(time.Second)
	select {
	case <-fixture.observer:
		timer.Stop()
	case <-timer.C:
		t.Fatal("No signal sent by diffstore")
	}

	upserted, deleted, err := diffstore.Diff()
	if err != nil {
		t.Fatal(err)
	}

	if len(upserted) != 1 {
		t.Fatal("Initial upserted not one")
	}

	if len(deleted) != 0 {
		t.Fatal("Initial deleted not zero")
	}

	// Add an object after init

	err = tracker.Add(&v1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name: "svc-b",
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	timer = time.NewTimer(time.Second)
	select {
	case <-fixture.observer:
		timer.Stop()
	case <-timer.C:
		t.Fatal("No signal sent by diffstore")
	}

	upserted, deleted, err = diffstore.Diff()
	if err != nil {
		t.Fatal(err)
	}

	if len(upserted) != 1 {
		t.Fatal("Runtime upserted not one")
	}

	if len(deleted) != 0 {
		t.Fatal("Runtime deleted not zero")
	}

	// Delete an object after init

	err = tracker.Delete(v1.SchemeGroupVersion.WithResource("services"), "", "svc-b")
	if err != nil {
		t.Fatal(err)
	}

	timer = time.NewTimer(time.Second)
	select {
	case <-fixture.observer:
		timer.Stop()
	case <-timer.C:
		t.Fatal("No signal sent by diffstore")
	}

	upserted, deleted, err = diffstore.Diff()
	if err != nil {
		t.Fatal(err)
	}

	if len(upserted) != 0 {
		t.Fatal("Runtime upserted not zero")
	}

	if len(deleted) != 1 {
		t.Fatal("Runtime deleted not one")
	}

	err = fixture.hive.Stop(context.Background())
	if err != nil {
		t.Fatal(err)
	}
}

// Test that multiple events are correctly combined.
func TestDiffUpsertCoalesce(t *testing.T) {
	fixture := newDiffStoreFixture()
	tracker := fixture.cs.Tracker()

	err := fixture.hive.Start(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	diffstore := fixture.diffFactory.NewStore()

	// Add first object
	err = tracker.Add(&v1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name: "svc-a",
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	// Add second object
	err = tracker.Add(&v1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name: "svc-b",
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	// Wait a second for changes to be processed
	time.Sleep(time.Second)

	// Check that we have a signal
	timer := time.NewTimer(time.Second)
	select {
	case <-fixture.observer:
		timer.Stop()
	case <-timer.C:
		t.Fatal("No signal sent by diffstore")
	}

	upserted, deleted, err := diffstore.Diff()
	if err != nil {
		t.Fatal(err)
	}

	if len(upserted) != 2 {
		t.Fatal("Expected 2 upserted objects")
	}

	if len(deleted) != 0 {
		t.Fatal("Expected 0 deleted objects")
	}

	// Update first object
	err = tracker.Update(
		v1.SchemeGroupVersion.WithResource("services"),
		&v1.Service{
			ObjectMeta: metav1.ObjectMeta{
				Name: "svc-a",
			},
			Spec: v1.ServiceSpec{
				ClusterIP: "1.2.3.4",
			},
		},
		"",
	)
	if err != nil {
		t.Fatal(err)
	}

	err = tracker.Delete(v1.SchemeGroupVersion.WithResource("services"), "", "svc-b")
	if err != nil {
		t.Fatal(err)
	}

	// Wait a second for changes to be processed
	time.Sleep(time.Second)

	// Check that we have a signal
	timer = time.NewTimer(time.Second)
	select {
	case <-fixture.observer:
		timer.Stop()
	case <-timer.C:
		t.Fatal("No signal sent by diffstore")
	}

	upserted, deleted, err = diffstore.Diff()
	if err != nil {
		t.Fatal(err)
	}

	if len(upserted) != 1 {
		t.Fatal("Expected 1 upserted object")
	}

	if len(deleted) != 1 {
		t.Fatal("Expected 1 deleted object")
	}

	// Update first object once
	err = tracker.Update(
		v1.SchemeGroupVersion.WithResource("services"),
		&v1.Service{
			ObjectMeta: metav1.ObjectMeta{
				Name: "svc-a",
			},
			Spec: v1.ServiceSpec{
				ClusterIP: "2.3.4.5",
			},
		},
		"",
	)
	if err != nil {
		t.Fatal(err)
	}

	// Update first object twice
	err = tracker.Update(
		v1.SchemeGroupVersion.WithResource("services"),
		&v1.Service{
			ObjectMeta: metav1.ObjectMeta{
				Name: "svc-a",
			},
			Spec: v1.ServiceSpec{
				ClusterIP: "3.4.5.6",
			},
		},
		"",
	)
	if err != nil {
		t.Fatal(err)
	}

	// Wait a second for changes to be processed
	time.Sleep(time.Second)

	// Check that we have a signal
	timer = time.NewTimer(time.Second)
	select {
	case <-fixture.observer:
		timer.Stop()
	case <-timer.C:
		t.Fatal("No signal sent by diffstore")
	}

	upserted, deleted, err = diffstore.Diff()
	if err != nil {
		t.Fatal(err)
	}

	if len(upserted) != 1 {
		t.Fatal("Expected 1 upserted object")
	}

	if len(deleted) != 0 {
		t.Fatal("Expected 1 deleted object")
	}

	if upserted[0].Spec.ClusterIP != "3.4.5.6" {
		t.Fatal("Expected to only see the latest update")
	}

	err = fixture.hive.Stop(context.Background())
	if err != nil {
		t.Fatal(err)
	}
}
