// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package unmanagedpods

import (
	"fmt"
	"testing"
	"time"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	k8sTesting "k8s.io/client-go/testing"
	"k8s.io/client-go/tools/cache"

	"github.com/cilium/cilium/operator/watchers"
	cilium_api_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client/testutils"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
)

// newTestController wires an unmanagedPodsController against a fresh set of
// watcher stores and a fake clientset. It resets all package-level global
// state so tests do not leak into each other.
func newTestController(t *testing.T) (*unmanagedPodsController, *k8sClient.FakeClientset) {
	t.Helper()

	logger := hivetest.Logger(t)
	fakeClient, clientset := k8sClient.NewFakeClientset(logger)

	// By default pod deletions succeed. Individual tests can prepend their own
	// reactor to simulate API failures.
	fakeClient.KubernetesFakeClientset.PrependReactor("delete", "pods",
		func(action k8sTesting.Action) (bool, runtime.Object, error) {
			return true, nil, nil
		})

	// Reset global state shared across reconcile cycles and tests.
	lastPodRestart = map[string]time.Time{}
	watchers.UnmanagedPodStore = cache.NewStore(cache.MetaNamespaceKeyFunc)
	watchers.CiliumEndpointStore = cache.NewIndexer(
		cache.DeletionHandlingMetaNamespaceKeyFunc,
		cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc},
	)

	c := &unmanagedPodsController{
		clientset:          clientset,
		metrics:            NewMetrics(),
		logger:             logger,
		interval:           15 * time.Second,
		podRestartSelector: "",
	}
	return c, fakeClient
}

// addUnmanagedPod seeds the unmanaged pod store with a Running pod that has no
// corresponding CiliumEndpoint. startedAgo controls the pod age; pass a value
// greater than unmanagedPodMinimalAge to make it restart-eligible.
func addUnmanagedPod(t *testing.T, name, namespace string, startedAgo time.Duration, hostNetwork bool) *slim_corev1.Pod {
	t.Helper()
	started := slim_metav1.Time{Time: time.Now().Add(-startedAgo)}
	pod := &slim_corev1.Pod{
		ObjectMeta: slim_metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		Spec: slim_corev1.PodSpec{
			HostNetwork: hostNetwork,
		},
		Status: slim_corev1.PodStatus{
			StartTime: &started,
		},
	}
	require.NoError(t, watchers.UnmanagedPodStore.Add(pod))
	return pod
}

// addManagedPod seeds a Running pod together with a matching CiliumEndpoint so
// the controller treats it as managed.
func addManagedPod(t *testing.T, name, namespace string, startedAgo time.Duration) {
	t.Helper()
	addUnmanagedPod(t, name, namespace, startedAgo, false)
	cep := &cilium_api_v2.CiliumEndpoint{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
	}
	require.NoError(t, watchers.CiliumEndpointStore.Add(cep))
}

// countDeletes returns the number of pod delete actions recorded against the
// (non-slim) Kubernetes fake clientset, which is what the controller uses to
// restart pods.
func countDeletes(fakeClient *k8sClient.FakeClientset) int {
	deletes := 0
	for _, action := range fakeClient.KubernetesFakeClientset.Actions() {
		if action.Matches("delete", "pods") {
			deletes++
		}
	}
	return deletes
}

// TestReconcileMetricReflectsCountWhenRestarting is the regression test for
// GH issue #46197: the gauge must report the real number of unmanaged pods even
// on a cycle where a pod is restarted.
func TestReconcileMetricReflectsCountWhenRestarting(t *testing.T) {
	c, fakeClient := newTestController(t)

	// Three unmanaged, restart-eligible pods (older than the minimal age).
	addUnmanagedPod(t, "pod-a", "ns", time.Minute, false)
	addUnmanagedPod(t, "pod-b", "ns", time.Minute, false)
	addUnmanagedPod(t, "pod-c", "ns", time.Minute, false)

	require.NoError(t, c.reconcile(t.Context()))

	// The gauge must equal the full count (3), not 0 and not a partial count,
	// despite a restart having been issued this cycle.
	assert.Equal(t, float64(3), c.metrics.UnmanagedPods.Get(),
		"gauge must reflect the full unmanaged pod count even when a pod is restarted")
	// Exactly one pod is restarted per cycle.
	assert.Equal(t, 1, countDeletes(fakeClient),
		"controller must restart at most one pod per reconcile cycle")
}

// TestReconcileMetricWithoutRestart verifies the count is published when no pod
// is eligible for a restart yet (all pods are younger than the minimal age).
func TestReconcileMetricWithoutRestart(t *testing.T) {
	c, fakeClient := newTestController(t)

	addUnmanagedPod(t, "pod-young-1", "ns", time.Second, false)
	addUnmanagedPod(t, "pod-young-2", "ns", time.Second, false)

	require.NoError(t, c.reconcile(t.Context()))

	assert.Equal(t, float64(2), c.metrics.UnmanagedPods.Get())
	assert.Equal(t, 0, countDeletes(fakeClient),
		"pods younger than the minimal age must not be restarted")
}

// TestReconcileNilStartTimeCountedNotRestarted verifies that an unmanaged pod
// without a StartTime (e.g. not yet started) is counted in the gauge but is not
// eligible for restart.
func TestReconcileNilStartTimeCountedNotRestarted(t *testing.T) {
	c, fakeClient := newTestController(t)

	pod := &slim_corev1.Pod{
		ObjectMeta: slim_metav1.ObjectMeta{
			Name:      "no-start-time",
			Namespace: "ns",
		},
	}
	require.NoError(t, watchers.UnmanagedPodStore.Add(pod))

	require.NoError(t, c.reconcile(t.Context()))

	assert.Equal(t, float64(1), c.metrics.UnmanagedPods.Get(),
		"a pod without a StartTime must still be counted as unmanaged")
	assert.Equal(t, 0, countDeletes(fakeClient),
		"a pod without a StartTime must not be restarted")
}

// TestReconcileManagedPodsNotCounted verifies that pods with a CiliumEndpoint
// and host-network pods are neither counted nor restarted.
func TestReconcileManagedPodsNotCounted(t *testing.T) {
	c, fakeClient := newTestController(t)

	addManagedPod(t, "managed", "ns", time.Minute)
	addUnmanagedPod(t, "host-net", "ns", time.Minute, true)
	addUnmanagedPod(t, "unmanaged", "ns", time.Minute, false)

	require.NoError(t, c.reconcile(t.Context()))

	assert.Equal(t, float64(1), c.metrics.UnmanagedPods.Get(),
		"only the single non-host-network unmanaged pod must be counted")
	assert.Equal(t, 1, countDeletes(fakeClient))
}

// TestReconcileZeroUnmanaged verifies the gauge is reset to 0 when there are no
// unmanaged pods.
func TestReconcileZeroUnmanaged(t *testing.T) {
	c, fakeClient := newTestController(t)

	addManagedPod(t, "managed", "ns", time.Minute)

	require.NoError(t, c.reconcile(t.Context()))

	assert.Equal(t, float64(0), c.metrics.UnmanagedPods.Get())
	assert.Equal(t, 0, countDeletes(fakeClient))
}

// TestReconcileRateLimit verifies that a pod restarted in a previous cycle is
// still counted but is not restarted again until the minimal interval elapses,
// and that the metric remains accurate across cycles.
func TestReconcileRateLimit(t *testing.T) {
	c, fakeClient := newTestController(t)

	addUnmanagedPod(t, "pod-a", "ns", time.Minute, false)
	// Pretend pod-a was just restarted, so it is on cooldown.
	lastPodRestart["ns/pod-a"] = time.Now()

	require.NoError(t, c.reconcile(t.Context()))

	assert.Equal(t, float64(1), c.metrics.UnmanagedPods.Get(),
		"a pod on restart cooldown must still be counted")
	assert.Equal(t, 0, countDeletes(fakeClient),
		"a pod on restart cooldown must not be restarted again")
}

// TestReconcileSurfacesDeleteError verifies that when the API server rejects the
// delete, the controller does not record a restart time (so it will retry) and
// the metric still reflects the count.
func TestReconcileSurfacesDeleteError(t *testing.T) {
	c, fakeClient := newTestController(t)

	fakeClient.KubernetesFakeClientset.PrependReactor("delete", "pods",
		func(action k8sTesting.Action) (bool, runtime.Object, error) {
			return true, nil, fmt.Errorf("synthetic delete failure")
		})

	addUnmanagedPod(t, "pod-a", "ns", time.Minute, false)

	require.NoError(t, c.reconcile(t.Context()))

	assert.Equal(t, float64(1), c.metrics.UnmanagedPods.Get())
	_, recorded := lastPodRestart["ns/pod-a"]
	assert.False(t, recorded, "a failed delete must not record a restart time")
}

// TestReconcileAllDeletesFailAttemptsEachRecordsNone verifies that when every
// delete fails, the controller attempts each eligible candidate in the cycle
// (it does not stall after the first failure) and records no restart, while the
// gauge still reflects the full count.
func TestReconcileAllDeletesFailAttemptsEachRecordsNone(t *testing.T) {
	c, fakeClient := newTestController(t)

	fakeClient.KubernetesFakeClientset.PrependReactor("delete", "pods",
		func(action k8sTesting.Action) (bool, runtime.Object, error) {
			return true, nil, fmt.Errorf("synthetic delete failure")
		})

	addUnmanagedPod(t, "pod-a", "ns", time.Minute, false)
	addUnmanagedPod(t, "pod-b", "ns", time.Minute, false)
	addUnmanagedPod(t, "pod-c", "ns", time.Minute, false)

	require.NoError(t, c.reconcile(t.Context()))

	assert.Equal(t, float64(3), c.metrics.UnmanagedPods.Get())
	assert.Equal(t, 3, countDeletes(fakeClient),
		"every eligible candidate must be attempted when deletes keep failing")
	assert.Empty(t, lastPodRestart,
		"no restart time must be recorded when all deletes fail")
}

// TestReconcileRetriesNextPodAfterDeleteFailure verifies that when a delete
// fails, the controller moves on to the next eligible pod in the same cycle
// (rather than giving up), and stops after the first successful restart.
func TestReconcileRetriesNextPodAfterDeleteFailure(t *testing.T) {
	c, fakeClient := newTestController(t)

	// Fail the first delete, then fall through to the default success reactor.
	failuresLeft := 1
	fakeClient.KubernetesFakeClientset.PrependReactor("delete", "pods",
		func(action k8sTesting.Action) (bool, runtime.Object, error) {
			if failuresLeft > 0 {
				failuresLeft--
				return true, nil, fmt.Errorf("synthetic delete failure")
			}
			return false, nil, nil
		})

	addUnmanagedPod(t, "pod-a", "ns", time.Minute, false)
	addUnmanagedPod(t, "pod-b", "ns", time.Minute, false)

	require.NoError(t, c.reconcile(t.Context()))

	assert.Equal(t, float64(2), c.metrics.UnmanagedPods.Get())
	// Two delete attempts: the first fails, the controller retries the next.
	assert.Equal(t, 2, countDeletes(fakeClient),
		"controller must try the next pod after a failed delete")
	assert.Len(t, lastPodRestart, 1,
		"exactly one successful restart must be recorded per cycle")
}
