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
	"fmt"

	"github.com/cilium/cilium/api/v1/models"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	ciliumDaemonSetName    = "cilium"
	operatorDeploymentName = "cilium-operator"
	relayDeploymentName    = "hubble-relay"
)

type K8sStatusCollector struct {
	client    k8sImplementation
	namespace string
}

type k8sImplementation interface {
	GetNamespace(ctx context.Context, namespace string, options metav1.GetOptions) (*corev1.Namespace, error)
	CiliumStatus(ctx context.Context, namespace, pod string) (*models.StatusResponse, error)
	GetDaemonSet(ctx context.Context, namespace, name string, options metav1.GetOptions) (*appsv1.DaemonSet, error)
	GetDeployment(ctx context.Context, namespace, name string, options metav1.GetOptions) (*appsv1.Deployment, error)
	ListPods(ctx context.Context, namespace string, options metav1.ListOptions) (*corev1.PodList, error)
}

func NewK8sStatusCollector(ctx context.Context, client k8sImplementation, namespace string) (*K8sStatusCollector, error) {
	if namespace == "" {
		n, err := client.GetNamespace(ctx, "cilium", metav1.GetOptions{})
		if err != nil {
			return nil, err
		}
		namespace = n.Name
	}

	return &K8sStatusCollector{
		client:    client,
		namespace: namespace,
	}, nil
}

func (k *K8sStatusCollector) deploymentStatus(ctx context.Context, status *Status, name string) error {
	d, err := k.client.GetDeployment(ctx, k.namespace, name, metav1.GetOptions{})
	if err != nil {
		return err
	}

	if d == nil {
		return fmt.Errorf("Deployment %s is not available", name)
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

	return nil
}

func (k *K8sStatusCollector) daemonSetStatus(ctx context.Context, status *Status, name string) error {
	daemonSet, err := k.client.GetDaemonSet(ctx, k.namespace, name, metav1.GetOptions{})
	if err != nil {
		return err
	}

	if daemonSet == nil {
		return fmt.Errorf("DaemomSet %s is not available", name)
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
	pods, err := k.client.ListPods(ctx, k.namespace, metav1.ListOptions{LabelSelector: filter})
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
			status.AddAggregatedWarning(name, pod.Name, fmt.Errorf("Pod is pending"))
		case corev1.PodRunning, corev1.PodSucceeded:
		case corev1.PodFailed:
			status.AddAggregatedError(name, pod.Name, fmt.Errorf("Pod has failed: %s - %s", pod.Status.Reason, pod.Status.Message))
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

func (k *K8sStatusCollector) Status(ctx context.Context) (*Status, error) {
	status := newStatus()

	err := k.daemonSetStatus(ctx, status, ciliumDaemonSetName)
	if err != nil {
		status.AddAggregatedError(ciliumDaemonSetName, ciliumDaemonSetName, err)
		status.CollectionError(err)
	}

	err = k.podStatus(ctx, status, ciliumDaemonSetName, "k8s-app=cilium", func(ctx context.Context, status *Status, name string, pod *corev1.Pod) {
		if pod.Status.Phase == corev1.PodRunning {
			s, err := k.client.CiliumStatus(ctx, k.namespace, pod.Name)
			status.parseStatusResponse(ciliumDaemonSetName, pod.Name, s, err)
			status.CiliumStatus[pod.Name] = s
		}
	})
	if err != nil {
		status.CollectionError(err)
	}

	err = k.deploymentStatus(ctx, status, operatorDeploymentName)
	if err != nil {
		status.AddAggregatedError(operatorDeploymentName, operatorDeploymentName, err)
		status.CollectionError(err)
	}

	err = k.podStatus(ctx, status, operatorDeploymentName, "name=cilium-operator", nil)
	if err != nil {
		status.CollectionError(err)
	}

	err = k.deploymentStatus(ctx, status, relayDeploymentName)
	if err != nil {
		if _, ok := status.PodState[relayDeploymentName]; !ok {
			status.AddAggregatedWarning(relayDeploymentName, relayDeploymentName, fmt.Errorf("Relay is not deployed"))
		} else {
			status.AddAggregatedError(relayDeploymentName, relayDeploymentName, err)
			status.CollectionError(err)
		}
	}

	// pod status for relay is only validated if the deployment exists
	if _, ok := status.PodState[relayDeploymentName]; ok {
		err = k.podStatus(ctx, status, relayDeploymentName, "k8s-app=hubble-relay", nil)
		if err != nil {
			status.CollectionError(err)
		}
	}

	return status, nil
}
