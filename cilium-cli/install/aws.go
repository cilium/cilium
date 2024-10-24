// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package install

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

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

const (
	AwsNodeImageFamilyAmazonLinux2    = "AmazonLinux2"
	AwsNodeImageFamilyAmazonLinux2023 = "AmazonLinux2023"
	AwsNodeImageFamilyBottlerocket    = "Bottlerocket"
	AwsNodeImageFamilyCustom          = "Custom"
	AwsNodeImageFamilyUbuntu          = "Ubuntu"
	AwsNodeImageFamilyWindows         = "Windows"
)

type awsClusterInfo struct {
	ImageID string `json:"ImageID"`
}

func (k *K8sInstaller) awsRetrieveNodeImageFamily() error {
	// setting default fallback value
	k.params.AWS.AwsNodeImageFamily = AwsNodeImageFamilyCustom

	bytes, err := k.eksctlExec("get", "nodegroup", "--cluster", k.client.ClusterName())
	if err != nil {
		k.Log("❌ Could not detect AWS node image family, defaulted to fallback value: %s", k.params.AWS.AwsNodeImageFamily)
		return err
	}

	clusterInfo := awsClusterInfo{}
	if err := json.Unmarshal(bytes, &clusterInfo); err != nil {
		return fmt.Errorf("unable to unmarshal eksctl output: %w", err)
	}

	ami := clusterInfo.ImageID
	switch {
	case strings.Contains("AL2_", ami):
		k.params.AWS.AwsNodeImageFamily = AwsNodeImageFamilyAmazonLinux2
	case strings.Contains("AL2023", ami):
		k.params.AWS.AwsNodeImageFamily = AwsNodeImageFamilyAmazonLinux2023
	case strings.Contains("BOTTLEROCKET", ami):
		k.params.AWS.AwsNodeImageFamily = AwsNodeImageFamilyBottlerocket
	case strings.Contains("UBUNTU", ami):
		k.params.AWS.AwsNodeImageFamily = AwsNodeImageFamilyUbuntu
	case strings.Contains("WINDOWS", ami):
		k.params.AWS.AwsNodeImageFamily = AwsNodeImageFamilyWindows
	default:
		k.params.AWS.AwsNodeImageFamily = AwsNodeImageFamilyCustom
	}

	k.Log("✅ Detected AWS node image family: %s", k.params.AWS.AwsNodeImageFamily)

	return nil
}

func getChainingMode(values map[string]interface{}) string {
	chainingMode, _, _ := unstructured.NestedString(values, "cni", "chainingMode")
	return chainingMode
}

func (k *K8sInstaller) awsSetupChainingMode(ctx context.Context, values map[string]interface{}) error {
	// detect chaining mode
	chainingMode := getChainingMode(values)

	// Do not stop AWS DS if we are running in chaining mode
	if chainingMode != "aws-cni" && !k.params.IsDryRun() {
		if _, err := k.client.GetDaemonSet(ctx, AwsNodeDaemonSetNamespace, AwsNodeDaemonSetName, metav1.GetOptions{}); err == nil {
			k.Log("🔥 Patching the %q DaemonSet to evict its pods...", AwsNodeDaemonSetName)
			patch := []byte(fmt.Sprintf(`{"spec":{"template":{"spec":{"nodeSelector":{"%s":"%s"}}}}}`, AwsNodeDaemonSetNodeSelectorKey, AwsNodeDaemonSetNodeSelectorValue))
			if _, err := k.client.PatchDaemonSet(ctx, AwsNodeDaemonSetNamespace, AwsNodeDaemonSetName, types.StrategicMergePatchType, patch, metav1.PatchOptions{}); err != nil {
				k.Log("❌ Unable to patch the %q DaemonSet", AwsNodeDaemonSetName)
				return err
			}
		}
	}

	return nil
}

// Wrapper function forcing `eksctl` output to be in JSON for unmarshalling purposes
func (k *K8sInstaller) eksctlExec(args ...string) ([]byte, error) {
	args = append(args, "--output", "json")
	return k.Exec("eksctl", args...)
}
