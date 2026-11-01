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
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	k8sTesting "k8s.io/client-go/testing"

	cilium_api_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client/testutils"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
)

// newTestController wires an unmanagedPodsController against empty fake stores
// and a fake clientset. Its pod restart selector is the one an empty
// --pod-restart-selector parses to, which matches every pod.
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

	podRestartSelector, err := labels.Parse("")
	require.NoError(t, err)

	c := &unmanagedPodsController{
		clientset:          clientset,
		metrics:            NewMetrics(),
		logger:             logger,
		interval:           15 * time.Second,
		podRestartSelector: podRestartSelector,
		cepStore:           &fakeCEPStore{ceps: map[resource.Key]*cilium_api_v2.CiliumEndpoint{}},
		podStore:           &fakePodStore{},
		lastPodRestart:     map[string]time.Time{},
	}
	return c, fakeClient
}

type fakeCEPStore struct {
	resource.Store[*cilium_api_v2.CiliumEndpoint]

	ceps map[resource.Key]*cilium_api_v2.CiliumEndpoint
}

func (s *fakeCEPStore) GetByKey(key resource.Key) (*cilium_api_v2.CiliumEndpoint, bool, error) {
	cep, ok := s.ceps[key]
	return cep, ok, nil
}

type fakePodStore struct {
	resource.Store[*slim_corev1.Pod]

	pods []*slim_corev1.Pod
}

func (s *fakePodStore) List() []*slim_corev1.Pod {
	return s.pods
}

// addPod seeds the controller's pod store.
func addPod(c *unmanagedPodsController, pod *slim_corev1.Pod) {
	store := c.podStore.(*fakePodStore)
	store.pods = append(store.pods, pod)
}

// addUnmanagedPod seeds the pod store with a Running pod that has no
// corresponding CiliumEndpoint. startedAgo controls the pod age; pass a value
// greater than unmanagedPodMinimalAge to make it restart-eligible.
func addUnmanagedPod(c *unmanagedPodsController, name, namespace string, startedAgo time.Duration, hostNetwork bool) *slim_corev1.Pod {
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
			Phase:     slim_corev1.PodRunning,
			StartTime: &started,
		},
	}
	addPod(c, pod)
	return pod
}

// addManagedPod seeds a Running pod together with a matching CiliumEndpoint so
// the controller treats it as managed.
func addManagedPod(c *unmanagedPodsController, name, namespace string, startedAgo time.Duration) {
	addUnmanagedPod(c, name, namespace, startedAgo, false)
	cep := &cilium_api_v2.CiliumEndpoint{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
	}
	c.cepStore.(*fakeCEPStore).ceps[resource.NewKey(cep)] = cep
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
	addUnmanagedPod(c, "pod-a", "ns", time.Minute, false)
	addUnmanagedPod(c, "pod-b", "ns", time.Minute, false)
	addUnmanagedPod(c, "pod-c", "ns", time.Minute, false)

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

	addUnmanagedPod(c, "pod-young-1", "ns", time.Second, false)
	addUnmanagedPod(c, "pod-young-2", "ns", time.Second, false)

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
		Status: slim_corev1.PodStatus{
			Phase: slim_corev1.PodRunning,
		},
	}
	addPod(c, pod)

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

	addManagedPod(c, "managed", "ns", time.Minute)
	addUnmanagedPod(c, "host-net", "ns", time.Minute, true)
	addUnmanagedPod(c, "unmanaged", "ns", time.Minute, false)

	require.NoError(t, c.reconcile(t.Context()))

	assert.Equal(t, float64(1), c.metrics.UnmanagedPods.Get(),
		"only the single non-host-network unmanaged pod must be counted")
	assert.Equal(t, 1, countDeletes(fakeClient))
}

// TestReconcileZeroUnmanaged verifies the gauge is reset to 0 when there are no
// unmanaged pods.
func TestReconcileZeroUnmanaged(t *testing.T) {
	c, fakeClient := newTestController(t)

	addManagedPod(c, "managed", "ns", time.Minute)

	require.NoError(t, c.reconcile(t.Context()))

	assert.Equal(t, float64(0), c.metrics.UnmanagedPods.Get())
	assert.Equal(t, 0, countDeletes(fakeClient))
}

// TestReconcileRateLimit verifies that a pod restarted in a previous cycle is
// still counted but is not restarted again until the minimal interval elapses,
// and that the metric remains accurate across cycles.
func TestReconcileRateLimit(t *testing.T) {
	c, fakeClient := newTestController(t)

	addUnmanagedPod(c, "pod-a", "ns", time.Minute, false)
	// Pretend pod-a was just restarted, so it is on cooldown.
	c.lastPodRestart["ns/pod-a"] = time.Now()

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

	addUnmanagedPod(c, "pod-a", "ns", time.Minute, false)

	require.NoError(t, c.reconcile(t.Context()))

	assert.Equal(t, float64(1), c.metrics.UnmanagedPods.Get())
	_, recorded := c.lastPodRestart["ns/pod-a"]
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

	addUnmanagedPod(c, "pod-a", "ns", time.Minute, false)
	addUnmanagedPod(c, "pod-b", "ns", time.Minute, false)
	addUnmanagedPod(c, "pod-c", "ns", time.Minute, false)

	require.NoError(t, c.reconcile(t.Context()))

	assert.Equal(t, float64(3), c.metrics.UnmanagedPods.Get())
	assert.Equal(t, 3, countDeletes(fakeClient),
		"every eligible candidate must be attempted when deletes keep failing")
	assert.Empty(t, c.lastPodRestart,
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

	addUnmanagedPod(c, "pod-a", "ns", time.Minute, false)
	addUnmanagedPod(c, "pod-b", "ns", time.Minute, false)

	require.NoError(t, c.reconcile(t.Context()))

	assert.Equal(t, float64(2), c.metrics.UnmanagedPods.Get())
	// Two delete attempts: the first fails, the controller retries the next.
	assert.Equal(t, 2, countDeletes(fakeClient),
		"controller must try the next pod after a failed delete")
	assert.Len(t, c.lastPodRestart, 1,
		"exactly one successful restart must be recorded per cycle")
}

// TestReconcileSkipsPodsNotMatchingSelector verifies that only pods matching
// the pod restart selector are counted and restarted, since the pod store holds
// every pod in the cluster.
func TestReconcileSkipsPodsNotMatchingSelector(t *testing.T) {
	c, fakeClient := newTestController(t)

	selector, err := labels.Parse("k8s-app=kube-dns")
	require.NoError(t, err)
	c.podRestartSelector = selector

	addUnmanagedPod(c, "coredns", "kube-system", time.Minute, false).Labels = map[string]string{"k8s-app": "kube-dns"}
	addUnmanagedPod(c, "other", "kube-system", time.Minute, false).Labels = map[string]string{"k8s-app": "other"}
	addUnmanagedPod(c, "unlabeled", "ns", time.Minute, false)

	require.NoError(t, c.reconcile(t.Context()))

	assert.Equal(t, float64(1), c.metrics.UnmanagedPods.Get(),
		"only the pod matching the selector must be counted")
	assert.Equal(t, 1, countDeletes(fakeClient))
}
