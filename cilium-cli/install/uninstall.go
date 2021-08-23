// SPDX-License-Identifier: Apache-2.0
// Copyright 2020 Authors of Cilium

package install

import (
	"context"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/cilium/cilium-cli/clustermesh"
	"github.com/cilium/cilium-cli/defaults"
	"github.com/cilium/cilium-cli/internal/k8s"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

var retryInterval = 2 * time.Second

type UninstallParameters struct {
	Namespace     string
	TestNamespace string
	Writer        io.Writer
	Wait          bool
}

type K8sUninstaller struct {
	client k8sInstallerImplementation
	params UninstallParameters
	flavor k8s.Flavor
}

func NewK8sUninstaller(client k8sInstallerImplementation, p UninstallParameters) *K8sUninstaller {
	return &K8sUninstaller{
		client: client,
		params: p,
	}
}

func (k *K8sUninstaller) Log(format string, a ...interface{}) {
	fmt.Fprintf(k.params.Writer, format+"\n", a...)
}

func (k *K8sUninstaller) Uninstall(ctx context.Context) error {
	if err := k.autodetect(ctx); err != nil {
		return err
	}

	k.Log("🔥 Deleting cilium-test namespace...")
	k.client.DeleteNamespace(ctx, k.params.TestNamespace, metav1.DeleteOptions{})

	k.Log("🔥 Deleting Service accounts...")
	k.client.DeleteServiceAccount(ctx, k.params.Namespace, defaults.AgentServiceAccountName, metav1.DeleteOptions{})
	k.client.DeleteServiceAccount(ctx, k.params.Namespace, defaults.OperatorServiceAccountName, metav1.DeleteOptions{})
	k.Log("🔥 Deleting ConfigMap...")
	k.client.DeleteConfigMap(ctx, k.params.Namespace, defaults.ConfigMapName, metav1.DeleteOptions{})
	k.Log("🔥 Deleting Cluster roles...")
	k.client.DeleteClusterRole(ctx, defaults.AgentClusterRoleName, metav1.DeleteOptions{})
	k.client.DeleteClusterRoleBinding(ctx, defaults.AgentClusterRoleName, metav1.DeleteOptions{})
	k.client.DeleteClusterRole(ctx, defaults.OperatorClusterRoleName, metav1.DeleteOptions{})
	k.client.DeleteClusterRoleBinding(ctx, defaults.OperatorClusterRoleName, metav1.DeleteOptions{})
	k.Log("🔥 Deleting agent DaemonSet...")
	k.client.DeleteDaemonSet(ctx, k.params.Namespace, defaults.AgentDaemonSetName, metav1.DeleteOptions{})
	k.Log("🔥 Deleting operator Deployment...")
	k.client.DeleteDeployment(ctx, k.params.Namespace, defaults.OperatorDeploymentName, metav1.DeleteOptions{})

	clustermesh.NewK8sClusterMesh(k.client, clustermesh.Parameters{
		Namespace: k.params.Namespace,
		Writer:    k.params.Writer,
	}).Disable(ctx)

	k.Log("🔥 Deleting certificates...")
	k.uninstallCerts(ctx)

	switch k.flavor.Kind {
	case k8s.KindEKS:
		bytes := []byte(fmt.Sprintf(`[{"op":"remove","path":"/spec/template/spec/nodeSelector/%s"}]`, strings.ReplaceAll(AwsNodeDaemonSetNodeSelectorKey, "/", "~1")))
		k.Log("⏪ Undoing the changes to the %q DaemonSet...", AwsNodeDaemonSetName)
		if _, err := k.client.PatchDaemonSet(ctx, AwsNodeDaemonSetNamespace, AwsNodeDaemonSetName, types.JSONPatchType, bytes, metav1.PatchOptions{}); err != nil {
			k.Log("❌ Failed to patch the %q DaemonSet, please remove it's node selector manually", AwsNodeDaemonSetName)
		}
	case k8s.KindGKE:
		k.Log("🔥 Deleting GKE Node Init DaemonSet...")
		k.client.DeleteDaemonSet(ctx, k.params.Namespace, gkeInitName, metav1.DeleteOptions{})

		k.Log("🔥 Deleting resource quotas...")
		k.client.DeleteResourceQuota(ctx, k.params.Namespace, defaults.AgentResourceQuota, metav1.DeleteOptions{})
		k.client.DeleteResourceQuota(ctx, k.params.Namespace, defaults.OperatorResourceQuota, metav1.DeleteOptions{})
	}

	if k.params.Wait {
		k.Log("⌛ Waiting for Cilium to be uninstalled...")

	retry:
		pods, err := k.client.ListPods(ctx, k.params.Namespace, metav1.ListOptions{LabelSelector: "k8s-app=cilium"})
		if err != nil {
			return err
		}

		if len(pods.Items) > 0 {
			time.Sleep(retryInterval)
			goto retry
		}

		k.Log("⌛ Waiting for %s namespace to be terminated...", k.params.TestNamespace)
	retryNamespace:
		// Wait for the test namespace to be terminated. Subsequent connectivity checks would fail
		// if the test namespace is in Terminating state.
		_, err = k.client.GetNamespace(ctx, k.params.TestNamespace, metav1.GetOptions{})
		if err == nil {
			time.Sleep(retryInterval)
			goto retryNamespace
		}
	}

	k.Log("✅ Cilium was successfully uninstalled.")

	return nil
}
