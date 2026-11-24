// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package status

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/go-openapi/strfmt"
	"github.com/stretchr/testify/assert"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/cilium-cli/defaults"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
)

var (
	fakeParameters = K8sStatusParameters{
		Namespace: "kube-system",
	}
)

type k8sStatusMockClient struct {
	daemonSet          map[string]*appsv1.DaemonSet
	deployment         map[string]*appsv1.Deployment
	podList            map[string]*corev1.PodList
	status             map[string]*models.StatusResponse
	ciliumEndpointList map[string]*ciliumv2.CiliumEndpointList
}

func newK8sStatusMockClient() (c *k8sStatusMockClient) {
	c = &k8sStatusMockClient{}
	c.reset()
	return
}

func (c *k8sStatusMockClient) reset() {
	c.daemonSet = map[string]*appsv1.DaemonSet{}
	c.podList = map[string]*corev1.PodList{}
	c.status = map[string]*models.StatusResponse{}
	c.ciliumEndpointList = map[string]*ciliumv2.CiliumEndpointList{}
}

func (c *k8sStatusMockClient) addPod(namespace, name, filter string, containers []corev1.Container, status corev1.PodStatus) {
	if c.podList[filter] == nil {
		c.podList[filter] = &corev1.PodList{}
	}

	c.podList[filter].Items = append(c.podList[filter].Items, corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		Spec: corev1.PodSpec{
			Containers: containers,
		},
		Status: status,
	})
}

func (c *k8sStatusMockClient) setDaemonSet(namespace, name, filter string, desired, ready, available, unavailable, updated int32, generation, obvsGeneration int64) {
	c.daemonSet = map[string]*appsv1.DaemonSet{}

	c.daemonSet[namespace+"/"+name] = &appsv1.DaemonSet{
		ObjectMeta: metav1.ObjectMeta{
			Name:       name,
			Namespace:  namespace,
			Generation: generation,
		},
		Status: appsv1.DaemonSetStatus{
			DesiredNumberScheduled: desired,
			NumberReady:            ready,
			NumberAvailable:        available,
			NumberUnavailable:      unavailable,
			UpdatedNumberScheduled: updated,
			ObservedGeneration:     obvsGeneration,
		},
	}

	c.status = map[string]*models.StatusResponse{}

	for i := range available {
		podName := fmt.Sprintf("%s-%d", name, i)
		c.addPod(namespace, podName, filter, []corev1.Container{{Image: "cilium:1.8"}}, corev1.PodStatus{Phase: corev1.PodRunning})

		c.status[podName] = &models.StatusResponse{
			Kubernetes: &models.K8sStatus{
				State: "Warning",
				Msg:   "Error1",
			},
			Controllers: []*models.ControllerStatus{
				{Name: "c1", Status: &models.ControllerStatusStatus{ConsecutiveFailureCount: 1, LastFailureMsg: "Error1", LastFailureTimestamp: strfmt.DateTime(time.Now().Add(-time.Minute))}},
				{Name: "c2", Status: &models.ControllerStatusStatus{ConsecutiveFailureCount: 4, LastFailureMsg: "Error2", LastFailureTimestamp: strfmt.DateTime(time.Now().Add(-2 * time.Minute))}},
				{Name: "c3", Status: &models.ControllerStatusStatus{LastFailureTimestamp: strfmt.DateTime(time.Now().Add(-3 * time.Minute))}},
			},
		}
	}

	for i := range unavailable {
		podName := fmt.Sprintf("%s-%d", name, i+available)
		c.addPod(namespace, podName, filter, []corev1.Container{{Image: "cilium:1.9"}}, corev1.PodStatus{Phase: corev1.PodFailed})
		c.status[podName] = &models.StatusResponse{
			Kubernetes: &models.K8sStatus{
				State: "Warning",
				Msg:   "Error1",
			},
			Controllers: []*models.ControllerStatus{
				{Name: "c1", Status: &models.ControllerStatusStatus{ConsecutiveFailureCount: 1, LastFailureMsg: "Error1", LastFailureTimestamp: strfmt.DateTime(time.Now().Add(-time.Minute))}},
				{Name: "c2", Status: &models.ControllerStatusStatus{ConsecutiveFailureCount: 4, LastFailureMsg: "Error2", LastFailureTimestamp: strfmt.DateTime(time.Now().Add(-2 * time.Minute))}},
				{Name: "c3", Status: &models.ControllerStatusStatus{LastFailureTimestamp: strfmt.DateTime(time.Now().Add(-3 * time.Minute))}},
			},
		}
	}
}

func (c *k8sStatusMockClient) GetDaemonSet(_ context.Context, namespace, name string, _ metav1.GetOptions) (*appsv1.DaemonSet, error) {
	return c.daemonSet[namespace+"/"+name], nil
}

func (c *k8sStatusMockClient) GetDeployment(_ context.Context, namespace, name string, _ metav1.GetOptions) (*appsv1.Deployment, error) {
	return c.deployment[namespace+"/"+name], nil
}

func (c *k8sStatusMockClient) GetConfigMap(ctx context.Context, namespace, name string, opts metav1.GetOptions) (*corev1.ConfigMap, error) {
	return &corev1.ConfigMap{}, nil
}

func (c *k8sStatusMockClient) ListPods(_ context.Context, _ string, options metav1.ListOptions) (*corev1.PodList, error) {
	return c.podList[options.LabelSelector], nil
}

func (c *k8sStatusMockClient) ListCiliumEndpoints(_ context.Context, _ string, options metav1.ListOptions) (*ciliumv2.CiliumEndpointList, error) {
	return c.ciliumEndpointList[options.LabelSelector], nil
}

func (c *k8sStatusMockClient) ContainerLogs(_ context.Context, _, _, _ string, _ time.Time, _ bool) (string, error) {
	return "[error] a sample cilium-agent error message", nil
}

func (c *k8sStatusMockClient) CiliumStatus(_ context.Context, _, pod string) (*models.StatusResponse, error) {
	s, ok := c.status[pod]
	if !ok {
		return nil, fmt.Errorf("pod %s not found", pod)
	}
	return s, nil
}

func (c *k8sStatusMockClient) KVStoreMeshStatus(_ context.Context, _, _ string) ([]*models.RemoteCluster, error) {
	return nil, errors.New("not implemented")
}

func (c *k8sStatusMockClient) CiliumDbgEndpoints(_ context.Context, _, _ string) ([]*models.Endpoint, error) {
	return nil, nil
}

func TestMockClient(t *testing.T) {
	client := newK8sStatusMockClient()
	assert.NotNil(t, client)
}

func TestStatus(t *testing.T) {
	client := newK8sStatusMockClient()
	assert.NotNil(t, client)

	collector, err := NewK8sStatusCollector(client, fakeParameters)
	assert.NoError(t, err)
	assert.NotNil(t, collector)

	client.setDaemonSet("kube-system", defaults.AgentDaemonSetName, defaults.AgentPodSelector, 10, 10, 10, 0, 10, 1, 1)
	status, err := collector.Status(context.Background())
	assert.NoError(t, err)
	assert.NotNil(t, status)
	assert.Equal(t, 10, status.PodState[defaults.AgentDaemonSetName].Desired)
	assert.Equal(t, 10, status.PodState[defaults.AgentDaemonSetName].Ready)
	assert.Equal(t, 10, status.PodState[defaults.AgentDaemonSetName].Available)
	assert.Equal(t, 0, status.PodState[defaults.AgentDaemonSetName].Unavailable)
	assert.Equal(t, 10, status.PhaseCount[defaults.AgentDaemonSetName][string(corev1.PodRunning)])
	assert.Equal(t, 0, status.PhaseCount[defaults.AgentDaemonSetName][string(corev1.PodFailed)])
	assert.Len(t, status.CiliumStatus, 10)

	client.reset()
	client.setDaemonSet("kube-system", defaults.AgentDaemonSetName, defaults.AgentPodSelector, 10, 5, 5, 5, 10, 2, 2)
	status, err = collector.Status(context.Background())
	assert.NoError(t, err)
	assert.NotNil(t, status)
	assert.Equal(t, 10, status.PodState[defaults.AgentDaemonSetName].Desired)
	assert.Equal(t, 5, status.PodState[defaults.AgentDaemonSetName].Ready)
	assert.Equal(t, 5, status.PodState[defaults.AgentDaemonSetName].Available)
	assert.Equal(t, 5, status.PodState[defaults.AgentDaemonSetName].Unavailable)
	assert.Equal(t, 5, status.PhaseCount[defaults.AgentDaemonSetName][string(corev1.PodRunning)])
	assert.Equal(t, 5, status.PhaseCount[defaults.AgentDaemonSetName][string(corev1.PodFailed)])
	assert.Len(t, status.CiliumStatus, 5)

	client.reset()
	client.setDaemonSet("kube-system", defaults.AgentDaemonSetName, defaults.AgentPodSelector, 10, 5, 5, 5, 10, 3, 3)
	delete(client.status, "cilium-2")
	status, err = collector.Status(context.Background())
	assert.NoError(t, err)
	assert.NotNil(t, status)
	assert.Equal(t, 10, status.PodState[defaults.AgentDaemonSetName].Desired)
	assert.Equal(t, 5, status.PodState[defaults.AgentDaemonSetName].Ready)
	assert.Equal(t, 5, status.PodState[defaults.AgentDaemonSetName].Available)
	assert.Equal(t, 5, status.PodState[defaults.AgentDaemonSetName].Unavailable)
	assert.Equal(t, 5, status.PhaseCount[defaults.AgentDaemonSetName][string(corev1.PodRunning)])
	assert.Equal(t, 5, status.PhaseCount[defaults.AgentDaemonSetName][string(corev1.PodFailed)])
	assert.Len(t, status.CiliumStatus, 5)
	assert.Nil(t, status.CiliumStatus["cilium-2"])

	client.reset()
	// observed generation behind
	client.setDaemonSet("kube-system", defaults.AgentDaemonSetName, defaults.AgentPodSelector, 5, 5, 5, 5, 5, 3, 2)
	status, err = collector.Status(context.Background())
	assert.NoError(t, err)
	assert.NotNil(t, status)
	assert.Len(t, status.Errors["cilium"]["cilium"].Errors, 1)
	assert.Regexp(t, ".*rollout has not started.*", status.Errors["cilium"]["cilium"].Errors[0].Error())

	client.setDaemonSet("kube-system", defaults.AgentDaemonSetName, defaults.AgentPodSelector, 5, 5, 5, 5, 1, 3, 3)
	status, err = collector.Status(context.Background())
	assert.NoError(t, err)
	assert.NotNil(t, status)
	assert.Len(t, status.Errors["cilium"]["cilium"].Errors, 1)
	assert.Regexp(t, ".*is rolling out.*", status.Errors["cilium"]["cilium"].Errors[0].Error())
}

func TestPodStatusSkipsSupersededRejection(t *testing.T) {
	client := newK8sStatusMockClient()
	collector, err := NewK8sStatusCollector(client, fakeParameters)
	assert.NoError(t, err)

	const relaySelector = "k8s-app=hubble-relay"

	// A leftover replica rejected by admission (TaintToleration) sits next to a
	// healthy running sibling created by the ReplicaSet. The rejected pod must
	// not be counted as an error.
	client.addPod("kube-system", "hubble-relay-running", relaySelector,
		[]corev1.Container{{Image: "hubble-relay:1.9"}},
		corev1.PodStatus{Phase: corev1.PodRunning})
	client.addPod("kube-system", "hubble-relay-rejected", relaySelector,
		[]corev1.Container{{Image: "hubble-relay:1.9"}},
		corev1.PodStatus{Phase: corev1.PodFailed, Reason: "TaintToleration", Message: "Pod was rejected"})

	status := newStatus()
	err = collector.podStatus(context.Background(), status, defaults.RelayDeploymentName, relaySelector, nil)
	assert.NoError(t, err)
	assert.Equal(t, 0, status.totalErrors())
	assert.Equal(t, 1, status.PhaseCount[defaults.RelayDeploymentName][string(corev1.PodFailed)])

	// A pod that actually ran and crashed carries an empty pod-level Reason and
	// must still be surfaced as an error.
	client.reset()
	client.addPod("kube-system", "hubble-relay-crashed", relaySelector,
		[]corev1.Container{{Image: "hubble-relay:1.9"}},
		corev1.PodStatus{Phase: corev1.PodFailed})

	status = newStatus()
	err = collector.podStatus(context.Background(), status, defaults.RelayDeploymentName, relaySelector, nil)
	assert.NoError(t, err)
	assert.Equal(t, 1, status.totalErrors())
}

func TestFormat(t *testing.T) {
	client := newK8sStatusMockClient()
	assert.NotNil(t, client)

	collector, err := NewK8sStatusCollector(client, fakeParameters)
	assert.NoError(t, err)
	assert.NotNil(t, collector)

	client.setDaemonSet("kube-system", defaults.AgentDaemonSetName, defaults.AgentPodSelector, 10, 5, 5, 5, 10, 4, 4)
	delete(client.status, "cilium-2")

	client.addPod("kube-system", "cilium-operator-1", "k8s-app=cilium-operator", []corev1.Container{{Image: "cilium-operator:1.9"}}, corev1.PodStatus{Phase: corev1.PodRunning})

	status, err := collector.Status(context.Background())
	assert.NoError(t, err)
	buf := status.Format()
	assert.Equal(t, byte('\n'), buf[len(buf)-1])

	var nilStatus *Status
	buf = nilStatus.Format()
	assert.Empty(t, buf)
}

// refreshWriter records the status refreshes written by Watch, calls onRefresh
// after each of them, and cancels the watch once it has seen the given number
// of refreshes.
type refreshWriter struct {
	refreshes []string
	cursorUps int
	stopAfter int
	onRefresh func(n int)
	cancel    context.CancelFunc
}

func (w *refreshWriter) Write(p []byte) (int, error) {
	if string(p) == "\033[A\033[2K" {
		w.cursorUps++
		return len(p), nil
	}
	w.refreshes = append(w.refreshes, string(p))
	if w.onRefresh != nil {
		w.onRefresh(len(w.refreshes))
	}
	if len(w.refreshes) == w.stopAfter {
		w.cancel()
	}
	return len(p), nil
}

func TestWatch(t *testing.T) {
	client := newK8sStatusMockClient()
	params := fakeParameters
	params.Output = OutputJSON
	params.WatchInterval = time.Millisecond
	collector, err := NewK8sStatusCollector(client, params)
	assert.NoError(t, err)

	client.setDaemonSet("kube-system", defaults.AgentDaemonSetName, defaults.AgentPodSelector, 10, 10, 10, 0, 10, 1, 1)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	w := &refreshWriter{
		stopAfter: 2,
		cancel:    cancel,
		onRefresh: func(n int) {
			if n == 1 {
				// The next refresh must pick up the change.
				client.reset()
				client.setDaemonSet("kube-system", defaults.AgentDaemonSetName, defaults.AgentPodSelector, 10, 5, 5, 5, 10, 1, 1)
			}
		},
	}

	assert.NoError(t, collector.Watch(ctx, w))
	assert.Len(t, w.refreshes, 2)

	for i, ready := range []int{10, 5} {
		var s struct {
			PodState map[string]PodStateCount `json:"pod_state"`
		}
		assert.NoError(t, json.Unmarshal([]byte(w.refreshes[i]), &s))
		assert.Equal(t, ready, s.PodState[defaults.AgentDaemonSetName].Ready)
	}
}

func TestWatchSummary(t *testing.T) {
	client := newK8sStatusMockClient()
	client.setDaemonSet("kube-system", defaults.AgentDaemonSetName, defaults.AgentPodSelector, 10, 10, 10, 0, 10, 1, 1)

	t.Run("interactive", func(t *testing.T) {
		params := fakeParameters
		params.Output = OutputSummary
		params.Interactive = true
		params.WatchInterval = time.Millisecond
		collector, err := NewK8sStatusCollector(client, params)
		assert.NoError(t, err)

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		w := &refreshWriter{stopAfter: 2, cancel: cancel}

		assert.NoError(t, collector.Watch(ctx, w))
		assert.Len(t, w.refreshes, 2)
		assert.Contains(t, w.refreshes[0], "Cilium:")
		// The second refresh redraws the first one in place.
		assert.Equal(t, countWrappedLines(w.refreshes[0]), w.cursorUps)
	})

	t.Run("non-interactive", func(t *testing.T) {
		params := fakeParameters
		params.Output = OutputSummary
		params.Interactive = false
		params.WatchInterval = time.Millisecond
		collector, err := NewK8sStatusCollector(client, params)
		assert.NoError(t, err)

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		w := &refreshWriter{stopAfter: 2, cancel: cancel}

		assert.NoError(t, collector.Watch(ctx, w))
		assert.Len(t, w.refreshes, 2)
		assert.Zero(t, w.cursorUps)
		for _, r := range w.refreshes {
			assert.Contains(t, r, "Cilium:")
		}
	})
}

func TestWatchCanceled(t *testing.T) {
	client := newK8sStatusMockClient()
	client.setDaemonSet("kube-system", defaults.AgentDaemonSetName, defaults.AgentPodSelector, 10, 10, 10, 0, 10, 1, 1)
	collector, err := NewK8sStatusCollector(client, fakeParameters)
	assert.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	w := &refreshWriter{}

	assert.NoError(t, collector.Watch(ctx, w))
	assert.Empty(t, w.refreshes)
}

func TestWatchInterval(t *testing.T) {
	assert.Equal(t, defaults.WaitRetryInterval, K8sStatusParameters{}.watchInterval())
	assert.Equal(t, defaults.WaitRetryInterval, K8sStatusParameters{WatchInterval: -time.Second}.watchInterval())
	assert.Equal(t, 10*time.Second, K8sStatusParameters{WatchInterval: 10 * time.Second}.watchInterval())
}

func TestWrappedLines(t *testing.T) {
	for _, tc := range []struct {
		name  string
		text  string
		width int
		want  int
	}{
		{name: "single line", text: "Cilium: OK\n", width: 80, want: 1},
		{name: "no trailing newline", text: "Cilium: OK", width: 80, want: 1},
		{name: "blank line", text: "a\n\nb\n", width: 80, want: 3},
		{name: "wrapped line", text: strings.Repeat("x", 81) + "\n", width: 80, want: 2},
		{name: "exact width", text: strings.Repeat("x", 80) + "\n", width: 80, want: 1},
		{name: "colour codes", text: Green + strings.Repeat("x", 10) + Reset + "\n", width: 10, want: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, wrappedLines(tc.text, tc.width))
		})
	}
}
