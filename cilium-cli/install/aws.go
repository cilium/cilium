// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package install

import (
	"context"
	"errors"
	"fmt"
	"strings"

	corev1 "k8s.io/api/core/v1"
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

func (k *K8sInstaller) awsRetrieveNodeImageFamily() error {
	// setting default fallback value
	k.params.AWS.AwsNodeImageFamily = AwsNodeImageFamilyCustom

	nodes, err := k.client.ListNodes(context.Background(), metav1.ListOptions{})
	if err != nil {
		k.Log("❌ Could not list cluster nodes, defaulted to fallback node image family value: %s", k.params.AWS.AwsNodeImageFamily)
		return err
	}

	ami, err := getNodeImage(nodes.Items)
	if err != nil {
		k.Log("❌ Could not detect AWS node image family, defaulted to fallback value: %s", k.params.AWS.AwsNodeImageFamily)
		return err
	}

	k.params.AWS.AwsNodeImageFamily = ami
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

func getNodeImage(nodes []corev1.Node) (string, error) {
	if len(nodes) == 0 {
		return "", errors.New("unable to detect node OS, cluster has no nodes")
	}

	amiFn := func(ami string) string {
		ami = strings.ToUpper(ami)
		switch {
		case strings.Contains(ami, "AMAZON LINUX 2023"):
			return AwsNodeImageFamilyAmazonLinux2023
		case strings.Contains(ami, "AMAZON LINUX 2"):
			return AwsNodeImageFamilyAmazonLinux2
		case strings.Contains(ami, "BOTTLEROCKET"):
			return AwsNodeImageFamilyBottlerocket
		case strings.Contains(ami, "UBUNTU"):
			return AwsNodeImageFamilyUbuntu
		case strings.Contains(ami, "WINDOWS"):
			return AwsNodeImageFamilyWindows
		default:
			return AwsNodeImageFamilyCustom
		}
	}

	ami := amiFn(nodes[0].Status.NodeInfo.OSImage)
	// verify that all cluster nodes use the same OS image
	// because currently mixed nodes setup is not supported
	for i := 1; i < len(nodes); i++ {
		nodeAmi := amiFn(nodes[i].Status.NodeInfo.OSImage)
		if ami != nodeAmi {
			return "", fmt.Errorf("cluster has nodes with different OS images: '%s' and '%s'", ami, nodeAmi)
		}
	}

	return ami, nil
}
