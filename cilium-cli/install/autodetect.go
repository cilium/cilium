// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package install

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	"github.com/cilium/cilium/cilium-cli/k8s"
)

func (k *K8sInstaller) detectDatapathMode(helmValues map[string]any) error {
	if k.params.DatapathMode != "" {
		k.Log("ℹ️  Custom datapath mode: %s", k.params.DatapathMode)
		return nil
	}

	routingMode, _, _ := unstructured.NestedString(helmValues, "routingMode")
	if routingMode == "native" {
		k.params.DatapathMode = DatapathNative
		return nil
	}
	if routingMode == "tunnel" {
		k.params.DatapathMode = DatapathTunnel
		return nil
	}

	switch k.flavor.Kind {
	case k8s.KindKind:
		k.params.DatapathMode = DatapathTunnel
	case k8s.KindMinikube:
		k.params.DatapathMode = DatapathTunnel
	case k8s.KindEKS:
		k.params.DatapathMode = DatapathAwsENI
	case k8s.KindGKE:
		k.params.DatapathMode = DatapathGKE
	case k8s.KindAKS:
		// When on AKS, we need to determine if the cluster is in BYOCNI mode before
		// determining which DatapathMode to use.
		if err := k.azureAutodetect(); err != nil {
			return err
		}

		// Azure IPAM is not available in BYOCNI mode
		if k.params.Azure.IsBYOCNI {
			k.params.DatapathMode = DatapathAKSBYOCNI
		} else {
			k.params.DatapathMode = DatapathAzure
		}
	default:
		k.params.DatapathMode = DatapathTunnel
	}

	return nil
}

func (k *K8sInstaller) autodetect(ctx context.Context) {
	k.flavor = k.client.AutodetectFlavor(ctx)

	if k.flavor.Kind != k8s.KindUnknown {
		k.Log("🔮 Auto-detected Kubernetes kind: %s", k.flavor.Kind)
	}
}

func getClusterName(helmValues map[string]any) string {
	clusterName, _, _ := unstructured.NestedString(helmValues, "cluster", "name")
	return clusterName
}

func trimEKSClusterARN(fullARN string) string {
	const prefix = "cluster/"
	idx := strings.LastIndex(fullARN, prefix)
	if idx == -1 {
		return fullARN
	}
	idx += len(prefix)
	if idx < len(fullARN) {
		return fullARN[idx:]
	}

	return ""
}

func (k *K8sInstaller) autodetectAndValidate(ctx context.Context, helmValues map[string]any) error {
	k.autodetect(ctx)

	k.Log("ℹ️  Using Cilium version %s", k.chartVersion)

	clusterName := getClusterName(helmValues)
	if clusterName != "" {
		k.params.ClusterName = clusterName
	}

	if k.params.ClusterName == "" {
		if k.flavor.ClusterName != "" {
			// Neither underscores, dots nor colons are allowed as part of the cluster name.
			name := strings.NewReplacer("_", "-", ".", "-", ":", "-").Replace(k.flavor.ClusterName)

			if k.flavor.Kind == k8s.KindEKS {
				name = trimEKSClusterARN(name)
			}

			k.Log("🔮 Auto-detected cluster name: %s", name)
			k.params.ClusterName = name
		}
	} else {
		k.Log("ℹ️  Using cluster name %q", k.params.ClusterName)
	}

	if err := k.detectDatapathMode(helmValues); err != nil {
		return err
	}

	k.autodetectKubeProxy(ctx, helmValues)
	return nil
}

func (k *K8sInstaller) autodetectKubeProxy(ctx context.Context, helmValues map[string]any) error {
	if k.flavor.Kind == k8s.KindK3s {
		return nil
	}

	kubeSysNameSpace := "kube-system"

	dsList, err := k.client.ListDaemonSet(ctx, kubeSysNameSpace, metav1.ListOptions{})
	if err != nil {
		k.Log("⏭️ Skipping auto kube-proxy detection")
		return nil
	}

	for _, ds := range dsList.Items {
		if strings.Contains(ds.Name, "kube-proxy") {
			k.Log("🔮 Auto-detected kube-proxy has been installed")
			return nil
		}
	}
	apiServerHost, apiServerPort := k.client.GetAPIServerHostAndPort()
	if k.flavor.Kind == k8s.KindKind {
		k.Log("ℹ️  Detecting real Kubernetes API server addr and port on Kind")

		// When we are using Kind, the API server addr & port is port forwarded
		es, err := k.client.GetEndpointSlice(ctx, "default", "kubernetes", metav1.GetOptions{})
		if err != nil {
			k.Log("❌ Couldn't find 'kubernetes' service endpoint on Kind")
			return fmt.Errorf("failed to detect API server endpoint")
		}

		if len(es.Endpoints) != 0 {
			endpoint := es.Endpoints[0]

			if len(endpoint.Addresses) != 0 {
				apiServerHost = endpoint.Addresses[0]
			} else {
				k.Log("❌ Couldn't find endpoint address of the 'kubernetes' service endpoint on Kind")
				return fmt.Errorf("failed to detect API server address")
			}

			if len(es.Ports) != 0 {
				apiServerPort = strconv.FormatInt(int64(*es.Ports[0].Port), 10)
			} else {
				k.Log("❌ Couldn't find endpoint port of the 'kubernetes' service endpoint on Kind")
				return fmt.Errorf("failed to detect API server address")
			}
		} else {
			k.Log("❌ Couldn't find 'kubernetes' service endpoint subset on Kind")
			return fmt.Errorf("failed to detect API server endpoint")
		}
	}

	if apiServerHost != "" && apiServerPort != "" {
		k.Log("🔮 Auto-detected kube-proxy has not been installed")
		k.Log("ℹ️  Cilium will fully replace all functionalities of kube-proxy")

		setIfUnset := func(key, value string) {
			_, found, _ := unstructured.NestedFieldNoCopy(helmValues, key)
			if !found {
				k.params.HelmOpts.Values = append(k.params.HelmOpts.Values,
					fmt.Sprintf("%s=%s", key, value))
			}
		}

		// Use HelmOpts to set auto kube-proxy installation
		setIfUnset("kubeProxyReplacement", "true")

		setIfUnset("k8sServiceHost", apiServerHost)
		setIfUnset("k8sServicePort", apiServerPort)
	}

	return nil
}
