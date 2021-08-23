// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Authors of Cilium

package install

import (
	"context"
	"fmt"
	"strings"

	"github.com/cilium/cilium-cli/defaults"
	"github.com/cilium/cilium-cli/status"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

func (k *K8sInstaller) Upgrade(ctx context.Context) error {
	daemonSet, err := k.client.GetDaemonSet(ctx, k.params.Namespace, defaults.AgentDaemonSetName, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("unable to retrieve DaemonSet of cilium-agent: %s", err)
	}

	deployment, err := k.client.GetDeployment(ctx, k.params.Namespace, defaults.OperatorDeploymentName, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("unable to retrieve Deployment of cilium-operator: %s", err)
	}

	var patched int

	if deployment.Spec.Template.Spec.Containers[0].Image == k.fqOperatorImage() {
		k.Log("✅ cilium-operator is already up to date")
	} else {
		k.Log("🚀 Upgrading cilium-operator to version %s...", k.fqOperatorImage())
		patch := []byte(`{"spec":{"template":{"spec":{"containers":[{"name": "cilium-operator", "image":"` + k.fqOperatorImage() + `"}]}}}}`)

		_, err = k.client.PatchDeployment(ctx, k.params.Namespace, defaults.OperatorDeploymentName, types.StrategicMergePatchType, patch, metav1.PatchOptions{})
		if err != nil {
			return fmt.Errorf("unable to patch Deployment %s with patch %q: %w", defaults.OperatorDeploymentName, patch, err)
		}

		patched++
	}

	agentImage := k.fqAgentImage()
	var containerPatches []string
	for _, c := range daemonSet.Spec.Template.Spec.Containers {
		if c.Image != agentImage {
			containerPatches = append(containerPatches, `{"name":"`+c.Name+`", "image":"`+agentImage+`"}`)
		}
	}
	var initContainerPatches []string
	for _, c := range daemonSet.Spec.Template.Spec.InitContainers {
		if c.Image != agentImage {
			initContainerPatches = append(initContainerPatches, `{"name":"`+c.Name+`", "image":"`+agentImage+`"}`)
		}
	}

	if len(containerPatches) == 0 && len(initContainerPatches) == 0 {
		k.Log("✅ Cilium is already up to date")
	} else {
		k.Log("🚀 Upgrading cilium to version %s...", k.fqAgentImage())

		patch := []byte(`{"spec":{"template":{"spec":{"containers":[` + strings.Join(containerPatches, ",") + `], "initContainers":[` + strings.Join(initContainerPatches, ",") + `]}}}}`)
		_, err = k.client.PatchDaemonSet(ctx, k.params.Namespace, defaults.AgentDaemonSetName, types.StrategicMergePatchType, patch, metav1.PatchOptions{})
		if err != nil {
			return fmt.Errorf("unable to patch DaemonSet %s with patch %q: %w", defaults.AgentDaemonSetName, patch, err)
		}

		patched++
	}

	if patched > 0 && k.params.Wait {
		k.Log("⌛ Waiting for Cilium to be upgraded...")
		collector, err := status.NewK8sStatusCollector(ctx, k.client, status.K8sStatusParameters{
			Namespace:       k.params.Namespace,
			Wait:            true,
			WaitDuration:    k.params.WaitDuration,
			WarningFreePods: []string{defaults.AgentDaemonSetName, defaults.OperatorDeploymentName},
		})
		if err != nil {
			return err
		}

		s, err := collector.Status(ctx)
		if err != nil {
			if s != nil {
				fmt.Println(s.Format())
			}
			return err
		}
	}

	return nil
}
