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

package install

import (
	"context"
	"fmt"
	"io"

	"github.com/cilium/cilium-cli/defaults"
	"github.com/cilium/cilium-cli/internal/k8s"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type UninstallParameters struct {
	Namespace string
	Writer    io.Writer
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

	k.Log("🔥 Deleting certificates...")
	k.uninstallCerts(ctx)

	switch k.flavor.Kind {
	case k8s.KindEKS:
		k.Log("⚠️  The aws-node DaemonSet will still be missing. You have to re-create it.")
	case k8s.KindGKE:
		k.Log("🔥 Deleting GKE Node Init DaemonSet...")
		k.client.DeleteDaemonSet(ctx, k.params.Namespace, gkeInitName, metav1.DeleteOptions{})

		k.Log("🔥 Deleting resource quotas...")
		k.client.DeleteResourceQuota(ctx, k.params.Namespace, defaults.AgentResourceQuota, metav1.DeleteOptions{})
		k.client.DeleteResourceQuota(ctx, k.params.Namespace, defaults.OperatorResourceQuota, metav1.DeleteOptions{})
	}

	return nil
}
