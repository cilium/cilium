// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package install

import (
	"context"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/cilium/cilium-cli/internal/utils"
	"github.com/cilium/cilium-cli/k8s"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type validationCheck interface {
	Name() string
	Check(ctx context.Context, k *K8sInstaller) error
}

var (
	validationChecks = map[k8s.Kind][]validationCheck{
		k8s.KindMinikube: {
			&minikubeVersionValidation{},
		},
		k8s.KindKind: {
			&kindVersionValidation{},
		},
	}

	clusterNameValidation = regexp.MustCompile(`^[a-zA-Z0-9]([-a-zA-Z0-9]*[a-zA-Z0-9])$`)
)

func (p Parameters) checkDisabled(name string) bool {
	for _, n := range p.DisableChecks {
		if n == name {
			return true
		}
	}
	return false
}

func (k *K8sUninstaller) autodetect(ctx context.Context) {
	k.flavor = k.client.AutodetectFlavor(ctx)

	if k.flavor.Kind != k8s.KindUnknown {
		k.Log("🔮 Auto-detected Kubernetes kind: %s", k.flavor.Kind)
	}
}

func (k *K8sInstaller) detectDatapathMode() error {
	if k.params.DatapathMode != "" {
		k.Log("ℹ️  Custom datapath mode: %s", k.params.DatapathMode)
		return nil
	}

	vals, err := k.getHelmValues()
	if err != nil {
		return err
	}

	routingMode := ""
	for _, val := range vals {
		val, ok := val.(string)
		if ok && strings.HasPrefix(val, "routingMode") {
			routingMode = strings.Split(val, "=")[1]
		}

	}
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

func getClusterName(helmValues map[string]interface{}) string {
	cluster, ok := helmValues["cluster"].(map[string]interface{})
	if !ok {
		return ""
	}
	clusterName, ok := cluster["name"].(string)
	if !ok {
		return ""
	}
	return clusterName
}

func (k *K8sInstaller) autodetectAndValidate(ctx context.Context, helmValues map[string]interface{}) error {
	k.autodetect(ctx)
	if len(validationChecks[k.flavor.Kind]) > 0 {
		k.Log("✨ Running %q validation checks", k.flavor.Kind)
		for _, check := range validationChecks[k.flavor.Kind] {
			name := check.Name()
			if k.params.checkDisabled(name) {
				k.Log("⏭️  Skipping disabled validation test %q", name)
				continue
			}

			if err := check.Check(ctx, k); err != nil {
				k.Log("❌ Validation test %s failed: %s", name, err)
				k.Log("ℹ️  You can disable the test with --disable-check=%s", name)
				return fmt.Errorf("validation check for kind %q failed: %w", k.flavor.Kind, err)
			}
		}
	}

	k.Log("ℹ️  Using Cilium version %s", k.chartVersion)

	// "cluster.name" Helm value takes precedence over --cluster-name flag.
	clusterName := getClusterName(helmValues)
	if clusterName != "" {
		k.params.ClusterName = clusterName
	}

	if k.params.ClusterName == "" {
		if k.flavor.ClusterName != "" {
			name := strings.ReplaceAll(k.flavor.ClusterName, "_", "-")
			k.Log("🔮 Auto-detected cluster name: %s", name)
			k.params.ClusterName = name
		}
	} else {
		k.Log("ℹ️  Using cluster name %q", k.params.ClusterName)
	}

	if err := k.detectDatapathMode(); err != nil {
		return err
	}

	// TODO: remove when removing "ipam" flag (marked as deprecated), kept for
	// backwards compatibility
	if k.params.IPAM != "" {
		k.Log("ℹ️  Custom IPAM mode: %s", k.params.IPAM)
	}

	if !utils.IsInHelmMode() {
		if strings.Contains(k.params.ClusterName, ".") {
			k.Log("❌ Cluster name %q cannot contain dots", k.params.ClusterName)
			return fmt.Errorf("invalid cluster name, dots are not allowed")
		}

		if !clusterNameValidation.MatchString(k.params.ClusterName) {
			k.Log("❌ Cluster name %q is not valid, must match regular expression: %s", k.params.ClusterName, clusterNameValidation)
			return fmt.Errorf("invalid cluster name")
		}
	}

	switch k.params.Encryption {
	case encryptionDisabled,
		encryptionIPsec,
		encryptionWireguard,
		encryptionUnspecified:
		// nothing to do for valid values
	default:
		k.Log("❌ Invalid encryption mode: %q", k.params.Encryption)
		return fmt.Errorf("invalid encryption mode")
	}

	k.autodetectKubeProxy(ctx)
	return k.autoEnableBPFMasq()
}

func (k *K8sInstaller) autodetectKubeProxy(ctx context.Context) error {
	if k.params.UserSetKubeProxyReplacement {
		return nil
	} else if k.flavor.Kind == k8s.KindK3s {
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
		eps, err := k.client.GetEndpoints(ctx, "default", "kubernetes", metav1.GetOptions{})
		if err != nil {
			k.Log("❌ Couldn't find 'kubernetes' service endpoint on Kind")
			return fmt.Errorf("failed to detect API server endpoint")
		}

		if len(eps.Subsets) != 0 {
			subset := eps.Subsets[0]

			if len(subset.Addresses) != 0 {
				apiServerHost = subset.Addresses[0].IP
			} else {
				k.Log("❌ Couldn't find endpoint address of the 'kubernetes' service endpoint on Kind")
				return fmt.Errorf("failed to detect API server address")
			}

			if len(subset.Ports) != 0 {
				apiServerPort = strconv.FormatInt(int64(subset.Ports[0].Port), 10)
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
		// Use HelmOpts to set auto kube-proxy installation
		k.params.HelmOpts.Values = append(k.params.HelmOpts.Values,
			"kubeProxyReplacement=strict",
			fmt.Sprintf("k8sServiceHost=%s", apiServerHost),
			fmt.Sprintf("k8sServicePort=%s", apiServerPort))
	}

	return nil
}

func (k *K8sInstaller) autoEnableBPFMasq() error {
	vals, err := k.getHelmValues()
	if err != nil {
		return err
	}

	// Auto-enable BPF masquerading if KPR=strict and IPv6=disabled
	foundKPRStrict := false
	foundMasq := false
	enabledIPv6 := false
	for _, param := range vals {
		param, ok := param.(string)
		if !ok {
			continue
		}

		if !foundKPRStrict && param == "kubeProxyReplacement=strict" {
			foundKPRStrict = true
			continue
		}
		if strings.HasPrefix(param, "bpf.masquerade") {
			foundMasq = true
			break
		}
		if strings.HasPrefix(param, "ipv6.enabled=true") {
			enabledIPv6 = true
			break
		}
	}

	if foundKPRStrict && !foundMasq && !enabledIPv6 {
		k.params.HelmOpts.Values = append(k.params.HelmOpts.Values,
			"bpf.masquerade=true")
	}

	return nil
}
