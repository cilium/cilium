// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package install

import (
	"context"
	"fmt"
	"io"
	"strings"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	"github.com/cilium/cilium-cli/clustermesh"
	"github.com/cilium/cilium-cli/defaults"
	"github.com/cilium/cilium-cli/k8s"
)

type UninstallParameters struct {
	Namespace            string
	TestNamespace        string
	Writer               io.Writer
	Wait                 bool
	HelmValuesSecretName string
	RedactHelmCertKeys   bool
	HelmChartDirectory   string
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
	k.autodetect(ctx)

	k.Log("🔥 Deleting agent DaemonSet...")
	k.client.DeleteDaemonSet(ctx, k.params.Namespace, defaults.AgentDaemonSetName, metav1.DeleteOptions{})
	// We need to wait for daemonset to be deleted before proceeding with further cleanups
	// as pods' daemonsets might still need to contact API Server, for example to remove node annotations.
	if k.params.Wait {
		k.Log("⌛ Waiting for agent DaemonSet to be uninstalled...")
		err := k.waitForPodsToBeDeleted(ctx)
		if err != nil {
			k.Log("❌ Error while waiting for deletion of agent DaemonSet: %v", err)
		} else {
			k.Log("🔥 Agent DaemonSet deleted successfully...")
		}
	}
	k.Log("🔥 Deleting operator Deployment...")
	k.client.DeleteDeployment(ctx, k.params.Namespace, defaults.OperatorDeploymentName, metav1.DeleteOptions{})
	k.Log("🔥 Deleting %s namespace...", defaults.IngressSecretsNamespace)
	k.client.DeleteNamespace(ctx, defaults.IngressSecretsNamespace, metav1.DeleteOptions{})
	k.Log("🔥 Deleting ConfigMap...")
	k.client.DeleteConfigMap(ctx, k.params.Namespace, defaults.ConfigMapName, metav1.DeleteOptions{})
	k.Log("🔥 Deleting Roles...")
	k.client.DeleteRole(ctx, k.params.Namespace, defaults.AgentConfigRoleName, metav1.DeleteOptions{})
	k.client.DeleteRoleBinding(ctx, k.params.Namespace, defaults.AgentConfigRoleName, metav1.DeleteOptions{})
	k.Log("🔥 Deleting Cluster roles...")
	k.client.DeleteClusterRole(ctx, defaults.AgentClusterRoleName, metav1.DeleteOptions{})
	k.client.DeleteClusterRoleBinding(ctx, defaults.AgentClusterRoleName, metav1.DeleteOptions{})
	k.client.DeleteClusterRole(ctx, defaults.OperatorClusterRoleName, metav1.DeleteOptions{})
	k.client.DeleteClusterRoleBinding(ctx, defaults.OperatorClusterRoleName, metav1.DeleteOptions{})
	k.Log("🔥 Deleting IngressClass...")
	k.client.DeleteIngressClass(ctx, defaults.IngressClassName, metav1.DeleteOptions{})
	k.Log("🔥 Deleting Ingress Service...")
	k.client.DeleteService(ctx, k.params.Namespace, defaults.IngressService, metav1.DeleteOptions{})
	k.Log("🔥 Deleting Ingress Endpoints...")
	k.client.DeleteEndpoints(ctx, k.params.Namespace, defaults.IngressService, metav1.DeleteOptions{})
	k.client.DeleteService(ctx, k.params.Namespace, defaults.IngressService, metav1.DeleteOptions{})
	k.Log("🔥 Deleting Ingress Secret Namespace...")
	k.client.DeleteNamespace(ctx, defaults.IngressSecretsNamespace, metav1.DeleteOptions{})

	k.Log("🔥 Deleting Service accounts...")
	k.client.DeleteServiceAccount(ctx, k.params.Namespace, defaults.AgentServiceAccountName, metav1.DeleteOptions{})
	k.client.DeleteServiceAccount(ctx, k.params.Namespace, defaults.OperatorServiceAccountName, metav1.DeleteOptions{})

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
		k.Log("🔥 Deleting resource quotas...")
		k.client.DeleteResourceQuota(ctx, k.params.Namespace, defaults.AgentResourceQuota, metav1.DeleteOptions{})
		k.client.DeleteResourceQuota(ctx, k.params.Namespace, defaults.OperatorResourceQuota, metav1.DeleteOptions{})
	}

	if needsNodeInit(k.flavor.Kind) {
		k.Log("🔥 Deleting node init daemonset...")
		k.client.DeleteDaemonSet(ctx, k.params.Namespace, defaults.NodeInitDaemonSetName, metav1.DeleteOptions{})
	}

	k.Log("🔥 Deleting secret with the helm values configuration...")
	k.client.DeleteSecret(ctx, k.params.Namespace, k.params.HelmValuesSecretName, metav1.DeleteOptions{})

	k.Log("✅ Cilium was successfully uninstalled.")

	return nil
}

func (k *K8sUninstaller) waitForPodsToBeDeleted(ctx context.Context) error {
	for {
		pods, err := k.client.ListPods(ctx, k.params.Namespace, metav1.ListOptions{LabelSelector: defaults.AgentPodSelector})
		if err != nil {
			return err
		}

		if len(pods.Items) > 0 {
			select {
			case <-ctx.Done():
				return fmt.Errorf("timeout waiting for pod deletion")
			case <-time.After(defaults.WaitRetryInterval):
			}
		} else {
			return nil
		}
	}
}
