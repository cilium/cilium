// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package install

import (
	"context"
	"fmt"
	"io"
	"strings"
	"time"

	"helm.sh/helm/v3/pkg/action"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	"github.com/cilium/cilium-cli/defaults"
)

type UninstallParameters struct {
	Namespace            string
	TestNamespace        string
	Writer               io.Writer
	Wait                 bool
	HelmValuesSecretName string
	RedactHelmCertKeys   bool
	HelmChartDirectory   string
	WorkerCount          int
	Timeout              time.Duration
}

type K8sUninstaller struct {
	client k8sInstallerImplementation
	params UninstallParameters
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

func (k *K8sUninstaller) UninstallWithHelm(ctx context.Context, actionConfig *action.Configuration) error {
	helmClient := action.NewUninstall(actionConfig)
	helmClient.Wait = k.params.Wait
	helmClient.Timeout = k.params.Timeout
	if _, err := helmClient.Run(defaults.HelmReleaseName); err != nil {
		return err
	}
	// If aws-node daemonset exists, remove io.cilium/aws-node-enabled node selector.
	if _, err := k.client.GetDaemonSet(ctx, AwsNodeDaemonSetNamespace, AwsNodeDaemonSetName, metav1.GetOptions{}); err != nil {
		return nil
	}
	return k.undoAwsNodeNodeSelector(ctx)
}

func (k *K8sUninstaller) undoAwsNodeNodeSelector(ctx context.Context) error {
	bytes := []byte(fmt.Sprintf(`[{"op":"remove","path":"/spec/template/spec/nodeSelector/%s"}]`, strings.ReplaceAll(AwsNodeDaemonSetNodeSelectorKey, "/", "~1")))
	k.Log("⏪ Undoing the changes to the %q DaemonSet...", AwsNodeDaemonSetName)
	_, err := k.client.PatchDaemonSet(ctx, AwsNodeDaemonSetNamespace, AwsNodeDaemonSetName, types.JSONPatchType, bytes, metav1.PatchOptions{})
	if err != nil {
		k.Log("❌ Failed to patch the %q DaemonSet, please remove it's node selector manually", AwsNodeDaemonSetName)
	}
	return err
}
