// Copyright 2020 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package status

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/cilium/cilium-cli/defaults"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/go-openapi/strfmt"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var retryInterval = 2 * time.Second

type K8sStatusParameters struct {
	Namespace       string
	Wait            bool
	WaitDuration    time.Duration
	WarningFreePods []string
}

type K8sStatusCollector struct {
	client k8sImplementation
	params K8sStatusParameters
}

type k8sImplementation interface {
	CiliumStatus(ctx context.Context, namespace, pod string) (*models.StatusResponse, error)
	GetDaemonSet(ctx context.Context, namespace, name string, options metav1.GetOptions) (*appsv1.DaemonSet, error)
	GetDeployment(ctx context.Context, namespace, name string, options metav1.GetOptions) (*appsv1.Deployment, error)
	ListPods(ctx context.Context, namespace string, options metav1.ListOptions) (*corev1.PodList, error)
}

func NewK8sStatusCollector(ctx context.Context, client k8sImplementation, params K8sStatusParameters) (*K8sStatusCollector, error) {
	return &K8sStatusCollector{
		client: client,
		params: params,
	}, nil
}

type ClusterConnectivityInfo struct {
	Ready          bool
	SharedServices int64
	Nodes          int64
	Identities     int64
	LastFailure    strfmt.DateTime
}

type ClusterMeshAgentConnectivityStatus struct {
	GlobalServices int64
	Clusters       map[string]*models.RemoteCluster
	Errors         ErrorCountMap
}

func (k *K8sStatusCollector) ClusterMeshConnectivity(ctx context.Context, ciliumPod string) (*ClusterMeshAgentConnectivityStatus, error) {
	ctx, cancel := context.WithTimeout(ctx, k.params.waitTimeout())
	defer cancel()

retry:
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	s, err := k.clusterMeshConnectivity(ctx, ciliumPod)
	if err != nil {
		if k.params.Wait {
			time.Sleep(retryInterval)
			goto retry
		}
	}

	// If we are waiting for a successful status then all clusters need to
	// be ready
	if k.params.Wait {
		for _, cluster := range s.Clusters {
			if !cluster.Ready {
				time.Sleep(retryInterval)
				goto retry
			}
		}
	}

	return s, err
}

var ErrClusterMeshStatusNotAvailable = errors.New("ClusterMesh status is not available")

func (k *K8sStatusCollector) clusterMeshConnectivity(ctx context.Context, ciliumPod string) (*ClusterMeshAgentConnectivityStatus, error) {
	c := &ClusterMeshAgentConnectivityStatus{
		Clusters: map[string]*models.RemoteCluster{},
	}

	status, err := k.client.CiliumStatus(ctx, k.params.Namespace, ciliumPod)
	if err != nil {
		return nil, fmt.Errorf("unable to determine cilium status: %w", err)
	}

	if status.ClusterMesh == nil {
		return nil, ErrClusterMeshStatusNotAvailable
	}

	c.GlobalServices = status.ClusterMesh.NumGlobalServices
	for _, cluster := range status.ClusterMesh.Clusters {
		c.Clusters[cluster.Name] = cluster
	}

	return c, nil
}

func (k *K8sStatusCollector) deploymentStatus(ctx context.Context, status *Status, name string) (bool, error) {
	d, err := k.client.GetDeployment(ctx, k.params.Namespace, name, metav1.GetOptions{})
	if k8serrors.IsNotFound(err) {
		return true, nil
	}

	if err != nil {
		return false, err
	}

	if d == nil {
		return false, fmt.Errorf("deployment %s is not available", name)
	}

	stateCount := PodStateCount{Type: "Deployment"}
	stateCount.Desired = int(d.Status.Replicas)
	stateCount.Ready = int(d.Status.ReadyReplicas)
	stateCount.Available = int(d.Status.AvailableReplicas)
	stateCount.Unavailable = int(d.Status.UnavailableReplicas)
	status.PodState[name] = stateCount

	notReady := stateCount.Desired - stateCount.Ready
	if notReady > 0 {
		status.AddAggregatedError(name, name, fmt.Errorf("%d pods of DaemonSet %s are not ready", notReady, name))
	}

	if unavailable := stateCount.Unavailable - notReady; unavailable > 0 {
		status.AddAggregatedWarning(name, name, fmt.Errorf("%d pods of DaemonSet %s are not available", unavailable, name))
	}

	return false, nil
}

func (k *K8sStatusCollector) daemonSetStatus(ctx context.Context, status *Status, name string) error {
	daemonSet, err := k.client.GetDaemonSet(ctx, k.params.Namespace, name, metav1.GetOptions{})
	if err != nil {
		return err
	}

	if daemonSet == nil {
		return fmt.Errorf("DaemonSet %s is not available", name)
	}

	stateCount := PodStateCount{Type: "DaemonSet"}
	stateCount.Desired = int(daemonSet.Status.DesiredNumberScheduled)
	stateCount.Ready = int(daemonSet.Status.NumberReady)
	stateCount.Available = int(daemonSet.Status.NumberAvailable)
	stateCount.Unavailable = int(daemonSet.Status.NumberUnavailable)
	status.PodState[name] = stateCount

	notReady := int(daemonSet.Status.DesiredNumberScheduled) - int(daemonSet.Status.NumberReady)
	if notReady > 0 {
		status.AddAggregatedError(name, name, fmt.Errorf("%d pods of DaemonSet %s are not ready", notReady, name))
	}

	if unavailable := int(daemonSet.Status.NumberUnavailable) - notReady; unavailable > 0 {
		status.AddAggregatedWarning(name, name, fmt.Errorf("%d pods of DaemonSet %s are not available", unavailable, name))
	}

	return nil
}

type podStatusCallback func(ctx context.Context, status *Status, name string, pod *corev1.Pod)

func (k *K8sStatusCollector) podStatus(ctx context.Context, status *Status, name, filter string, callback podStatusCallback) error {
	pods, err := k.client.ListPods(ctx, k.params.Namespace, metav1.ListOptions{LabelSelector: filter})
	if err != nil {
		return err
	}

	if pods == nil {
		return fmt.Errorf("no pods found")
	}

	phaseCount, imageCount := MapCount{}, MapCount{}

	for _, pod := range pods.Items {
		phaseCount[string(pod.Status.Phase)]++

		switch pod.Status.Phase {
		case corev1.PodPending:
			status.AddAggregatedWarning(name, pod.Name, fmt.Errorf("pod is pending"))
		case corev1.PodRunning, corev1.PodSucceeded:
		case corev1.PodFailed:
			status.AddAggregatedError(name, pod.Name, fmt.Errorf("pod has failed: %s - %s", pod.Status.Reason, pod.Status.Message))
		}

		for _, container := range pod.Spec.Containers {
			imageCount[container.Image]++
		}

		if callback != nil {
			callback(ctx, status, name, &pod)
		}
	}

	status.PhaseCount[name] = phaseCount
	status.ImageCount[name] = imageCount

	return nil
}

func (s K8sStatusParameters) waitTimeout() time.Duration {
	if s.WaitDuration != time.Duration(0) {
		return s.WaitDuration
	}

	return 5 * time.Minute
}

func (k *K8sStatusCollector) statusIsReady(s *Status) bool {
	if s.totalErrors() > 0 {
		return false
	}

	for _, name := range k.params.WarningFreePods {
		if a := s.Errors[name]; a != nil {
			for _, c := range a {
				if len(c.Warnings) > 0 || len(c.Errors) > 0 {
					return false
				}
			}
		}
	}

	return true
}

func (k *K8sStatusCollector) Status(ctx context.Context) (*Status, error) {
	var mostRecentStatus *Status

	ctx, cancel := context.WithTimeout(ctx, k.params.waitTimeout())
	defer cancel()

retry:
	select {
	case <-ctx.Done():
		return mostRecentStatus, fmt.Errorf("timeout while waiting for status to become successful: %w", ctx.Err())
	default:
	}

	s, err := k.status(ctx)
	// We collect the most recent status that even if the last status call
	// fails, we can still display the most recent status
	if s != nil {
		mostRecentStatus = s
	}
	if (err != nil || !k.statusIsReady(s)) && k.params.Wait {
		time.Sleep(2 * time.Second)
		goto retry
	}

	return mostRecentStatus, err
}

func (k *K8sStatusCollector) status(ctx context.Context) (*Status, error) {
	status := newStatus()

	err := k.daemonSetStatus(ctx, status, defaults.AgentDaemonSetName)
	if err != nil {
		status.AddAggregatedError(defaults.AgentDaemonSetName, defaults.AgentDaemonSetName, err)
		status.CollectionError(err)
	}

	err = k.podStatus(ctx, status, defaults.AgentDaemonSetName, "k8s-app=cilium", func(ctx context.Context, status *Status, name string, pod *corev1.Pod) {
		if pod.Status.Phase == corev1.PodRunning {
			s, err := k.client.CiliumStatus(ctx, k.params.Namespace, pod.Name)
			status.parseStatusResponse(defaults.AgentDaemonSetName, pod.Name, s, err)
			status.CiliumStatus[pod.Name] = s
		}
	})
	if err != nil {
		status.CollectionError(err)
	}

	disabled, err := k.deploymentStatus(ctx, status, defaults.OperatorDeploymentName)
	status.SetDisabled(defaults.OperatorDeploymentName, defaults.OperatorDeploymentName, disabled)
	if err != nil {
		status.AddAggregatedError(defaults.OperatorDeploymentName, defaults.OperatorDeploymentName, err)
		status.CollectionError(err)
	}

	err = k.podStatus(ctx, status, defaults.OperatorDeploymentName, "name=cilium-operator", nil)
	if err != nil {
		status.CollectionError(err)
	}

	disabled, err = k.deploymentStatus(ctx, status, defaults.RelayDeploymentName)
	status.SetDisabled(defaults.RelayDeploymentName, defaults.RelayDeploymentName, disabled)
	if err != nil {
		if _, ok := status.PodState[defaults.RelayDeploymentName]; !ok {
			status.AddAggregatedWarning(defaults.RelayDeploymentName, defaults.RelayDeploymentName, fmt.Errorf("hubble relay is not deployed"))
		} else {
			status.AddAggregatedError(defaults.RelayDeploymentName, defaults.RelayDeploymentName, err)
			status.CollectionError(err)
		}
	}

	// pod status for relay is only validated if the deployment exists
	if _, ok := status.PodState[defaults.RelayDeploymentName]; ok {
		err = k.podStatus(ctx, status, defaults.RelayDeploymentName, "k8s-app=hubble-relay", nil)
		if err != nil {
			status.CollectionError(err)
		}
	}

	disabled, err = k.deploymentStatus(ctx, status, defaults.ClusterMeshDeploymentName)
	status.SetDisabled(defaults.ClusterMeshDeploymentName, defaults.ClusterMeshDeploymentName, disabled)
	if err != nil {
		if _, ok := status.PodState[defaults.ClusterMeshDeploymentName]; !ok {
			status.AddAggregatedWarning(defaults.ClusterMeshDeploymentName, defaults.ClusterMeshDeploymentName, fmt.Errorf("clustermesh is not deployed"))
		} else {
			status.AddAggregatedError(defaults.ClusterMeshDeploymentName, defaults.ClusterMeshDeploymentName, err)
			status.CollectionError(err)
		}
	}

	// pod status for relay is only validated if the deployment exists
	if _, ok := status.PodState[defaults.ClusterMeshDeploymentName]; ok {
		err = k.podStatus(ctx, status, defaults.ClusterMeshDeploymentName, "k8s-app=clustermesh-apiserver", nil)
		if err != nil {
			status.CollectionError(err)
		}
	}

	return status, nil
}
