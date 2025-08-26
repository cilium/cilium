// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package install

import (
	"context"
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"
)

const (
	AwsNodeDaemonSetName              = "aws-node"
	AwsNodeDaemonSetNamespace         = "kube-system"
	AwsNodeDaemonSetNodeSelectorKey   = "io.cilium/aws-node-enabled"
	AwsNodeDaemonSetNodeSelectorValue = "true"
)

func getChainingMode(values map[string]any) string {
	chainingMode, _, _ := unstructured.NestedString(values, "cni", "chainingMode")
	return chainingMode
}

func (k *K8sInstaller) awsSetupChainingMode(ctx context.Context, values map[string]any) error {
	// detect chaining mode
	chainingMode := getChainingMode(values)

	// Do not stop AWS DS if we are running in chaining mode
	if chainingMode != "aws-cni" && !k.params.IsDryRun() {
		if _, err := k.client.GetDaemonSet(ctx, AwsNodeDaemonSetNamespace, AwsNodeDaemonSetName, metav1.GetOptions{}); err == nil {
			k.Log("🔥 Patching the %q DaemonSet to evict its pods...", AwsNodeDaemonSetName)
			patch := fmt.Appendf(nil, `{"spec":{"template":{"spec":{"nodeSelector":{"%s":"%s"}}}}}`, AwsNodeDaemonSetNodeSelectorKey, AwsNodeDaemonSetNodeSelectorValue)
			if _, err := k.client.PatchDaemonSet(ctx, AwsNodeDaemonSetNamespace, AwsNodeDaemonSetName, types.StrategicMergePatchType, patch, metav1.PatchOptions{}); err != nil {
				k.Log("❌ Unable to patch the %q DaemonSet", AwsNodeDaemonSetName)
				return err
			}
		}
	}

	return nil
}
