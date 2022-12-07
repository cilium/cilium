// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package resource_test

import (
	"context"
	"testing"

	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestObjectTracker(t *testing.T) {
	var (
		node1 = &corev1.Node{
			ObjectMeta: metav1.ObjectMeta{Name: "node1"},
		}
		node2 = &corev1.Node{
			ObjectMeta: metav1.ObjectMeta{Name: "node2"},
		}

		fakeClient, cs = k8sClient.NewFakeClientset()

		events  <-chan resource.Event[*corev1.Node]
		tracker resource.ObjectTracker[*corev1.Node]
	)

	// Create couple of initial objects
	fakeClient.KubernetesFakeClientset.Tracker().Create(
		corev1.SchemeGroupVersion.WithResource("nodes"),
		node1.DeepCopy(), "")
	fakeClient.KubernetesFakeClientset.Tracker().Create(
		corev1.SchemeGroupVersion.WithResource("nodes"),
		node2.DeepCopy(), "")

	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	hive := hive.New(
		cell.Provide(func() k8sClient.Clientset { return cs }),
		nodesResource,
		cell.Invoke(func(r resource.Resource[*corev1.Node]) {
			tracker = r.Tracker(ctx)
			events = tracker.Events()
		}))

	if err := hive.Start(ctx); err != nil {
		t.Fatalf("hive.Start failed: %s", err)
	}

	// On start of tracking, event should be emitted if the object
	// exists.
	tracker.Track(resource.Key{Name: "nonexisting"})
	tracker.Track(resource.Key{Name: "node1"})

	ev := <-events
	assert.Equal(t, resource.Upsert, ev.Kind)
	assert.Equal(t, ev.Key.Name, "node1")
	ev.Done(nil)

	// Update both nodes
	node1.Status.Phase = "node1-update1"
	fakeClient.KubernetesFakeClientset.Tracker().Update(
		corev1.SchemeGroupVersion.WithResource("nodes"),
		node1.DeepCopy(), "")
	node2.Status.Phase = "node2-update1"
	fakeClient.KubernetesFakeClientset.Tracker().Update(
		corev1.SchemeGroupVersion.WithResource("nodes"),
		node2.DeepCopy(), "")

	// Only node1 event should be seen.
	ev = <-events
	assert.Equal(t, resource.Upsert, ev.Kind)
	assert.Equal(t, ev.Key.Name, "node1")
	assert.Equal(t, ev.Object.Status.Phase, corev1.NodePhase("node1-update1"))
	ev.Done(nil)

	// After untrack we should not get updates.
	tracker.Untrack(resource.Key{Name: "node1"})

	node1.Status.Phase = "node1-update2"
	fakeClient.KubernetesFakeClientset.Tracker().Update(
		corev1.SchemeGroupVersion.WithResource("nodes"),
		node1.DeepCopy(), "")

	fakeClient.KubernetesFakeClientset.Tracker().Delete(
		corev1.SchemeGroupVersion.WithResource("nodes"),
		"", "some-node")

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
