// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package manager

import (
	"context"
	"testing"
	"time"

	"github.com/cilium/cilium/pkg/bgpv1/agent"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slimv1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	v1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	slim_fake "github.com/cilium/cilium/pkg/k8s/slim/k8s/client/clientset/versioned/fake"
	"github.com/cilium/cilium/pkg/k8s/utils"
)

type DiffStoreFixture struct {
	diffStore DiffStore[*slimv1.Service]
	signaler  agent.Signaler
	slimCs    *slim_fake.Clientset
	hive      *hive.Hive
}

func newDiffStoreFixture() *DiffStoreFixture {
	fixture := &DiffStoreFixture{}

	// Create a new faked CRD client set with the pools as initial objects
	fixture.slimCs = slim_fake.NewSimpleClientset()

	// Construct a new Hive with faked out dependency cells.
	fixture.hive = hive.New(
		cell.Provide(func(lc hive.Lifecycle, c k8sClient.Clientset) resource.Resource[*slimv1.Service] {
			return resource.New[*slimv1.Service](
				lc, utils.ListerWatcherFromTyped[*slimv1.ServiceList](
					c.Slim().CoreV1().Services(""),
				),
			)
		}),

		// Provide the faked client cells directly
		cell.Provide(func() k8sClient.Clientset {
			return &k8sClient.FakeClientset{
				SlimFakeClientset: fixture.slimCs,
			}
		}),

		cell.Provide(agent.NewSignaler),

		cell.Invoke(func(
			signaler agent.Signaler,
			diffFactory DiffStore[*slimv1.Service],
		) {
			fixture.signaler = signaler
			fixture.diffStore = diffFactory
		}),

		cell.Provide(NewDiffStore[*slimv1.Service]),
	)

	return fixture
}

// Test that adding and deleting objects trigger signals
func TestDiffSignal(t *testing.T) {
	fixture := newDiffStoreFixture()
	tracker := fixture.slimCs.Tracker()

	// Add an initial object.
	err := tracker.Add(&slimv1.Service{
		ObjectMeta: v1.ObjectMeta{
			Name: "service-a",
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	err = fixture.hive.Start(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	timer := time.NewTimer(5 * time.Second)
	select {
	case <-fixture.signaler.Sig:
		timer.Stop()
	case <-timer.C:
		t.Fatal("No signal sent by diffstore")
	}

	upserted, deleted, err := fixture.diffStore.Diff()
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

	err = tracker.Add(&slimv1.Service{
		ObjectMeta: v1.ObjectMeta{
			Name: "service-b",
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	timer = time.NewTimer(5 * time.Second)
	select {
	case <-fixture.signaler.Sig:
		timer.Stop()
	case <-timer.C:
		t.Fatal("No signal sent by diffstore")
	}

	upserted, deleted, err = fixture.diffStore.Diff()
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

	err = tracker.Delete(slimv1.SchemeGroupVersion.WithResource("services"), "", "service-b")
	if err != nil {
		t.Fatal(err)
	}

	timer = time.NewTimer(5 * time.Second)
	select {
	case <-fixture.signaler.Sig:
		timer.Stop()
	case <-timer.C:
		t.Fatal("No signal sent by diffstore")
	}

	upserted, deleted, err = fixture.diffStore.Diff()
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
	tracker := fixture.slimCs.Tracker()

	err := fixture.hive.Start(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	// Add first object
	err = tracker.Add(&slimv1.Service{
		ObjectMeta: v1.ObjectMeta{
			Name: "service-a",
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	// Add second object
	err = tracker.Add(&slimv1.Service{
		ObjectMeta: v1.ObjectMeta{
			Name: "service-b",
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	// Wait a second for changes to be processed
	time.Sleep(time.Second)

	// Check that we have a signal
	timer := time.NewTimer(5 * time.Second)
	select {
	case <-fixture.signaler.Sig:
		timer.Stop()
	case <-timer.C:
		t.Fatal("No signal sent by diffstore")
	}

	upserted, deleted, err := fixture.diffStore.Diff()
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
		slimv1.SchemeGroupVersion.WithResource("services"),
		&slimv1.Service{
			ObjectMeta: v1.ObjectMeta{
				Name: "service-a",
			},
			Spec: slimv1.ServiceSpec{
				ClusterIP: "1.2.3.4",
			},
		},
		"",
	)
	if err != nil {
		t.Fatal(err)
	}

	err = tracker.Delete(slimv1.SchemeGroupVersion.WithResource("services"), "", "service-b")
	if err != nil {
		t.Fatal(err)
	}

	// Wait a second for changes to be processed
	time.Sleep(time.Second)

	// Check that we have a signal
	timer = time.NewTimer(5 * time.Second)
	select {
	case <-fixture.signaler.Sig:
		timer.Stop()
	case <-timer.C:
		t.Fatal("No signal sent by diffstore")
	}

	upserted, deleted, err = fixture.diffStore.Diff()
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
		slimv1.SchemeGroupVersion.WithResource("services"),
		&slimv1.Service{
			ObjectMeta: v1.ObjectMeta{
				Name: "service-a",
			},
			Spec: slimv1.ServiceSpec{
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
		slimv1.SchemeGroupVersion.WithResource("services"),
		&slimv1.Service{
			ObjectMeta: v1.ObjectMeta{
				Name: "service-a",
			},
			Spec: slimv1.ServiceSpec{
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
	timer = time.NewTimer(5 * time.Second)
	select {
	case <-fixture.signaler.Sig:
		timer.Stop()
	case <-timer.C:
		t.Fatal("No signal sent by diffstore")
	}

	upserted, deleted, err = fixture.diffStore.Diff()
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
