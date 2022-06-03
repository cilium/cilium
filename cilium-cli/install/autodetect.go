// SPDX-License-Identifier: Apache-2.0
// Copyright 2020 Authors of Cilium

package install

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/cilium/cilium-cli/k8s"
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
		k8s.KindAKS: {
			&azureVersionValidation{},
		},
	}

	clusterNameValidation = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])$`)
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

func (k *K8sInstaller) detectDatapathMode(withKPR bool) {
	if k.params.DatapathMode != "" {
		k.Log("🔮 Custom datapath mode: %s", k.params.DatapathMode)
		return
	}

	switch k.flavor.Kind {
	case k8s.KindKind:
		k.params.DatapathMode = DatapathTunnel

		if withKPR && k.params.KubeProxyReplacement == "" {
			k.Log("ℹ️  kube-proxy-replacement disabled")
			k.params.KubeProxyReplacement = "disabled"
		}
	case k8s.KindMinikube:
		k.params.DatapathMode = DatapathTunnel
	case k8s.KindEKS:
		k.params.DatapathMode = DatapathAwsENI
	case k8s.KindGKE:
		k.params.DatapathMode = DatapathGKE
	case k8s.KindAKS:
		k.params.DatapathMode = DatapathAzure

		if withKPR && k.params.KubeProxyReplacement == "" {
			k.Log("ℹ️  kube-proxy-replacement disabled")
			k.params.KubeProxyReplacement = "disabled"
		}
	}

	if k.params.DatapathMode != "" {
		k.Log("🔮 Auto-detected datapath mode: %s", k.params.DatapathMode)
	}
}

func (k *K8sInstaller) autodetect(ctx context.Context) {
	k.flavor = k.client.AutodetectFlavor(ctx)

	if k.flavor.Kind != k8s.KindUnknown {
		k.Log("🔮 Auto-detected Kubernetes kind: %s", k.flavor.Kind)
	}
}

func (k *K8sInstaller) autodetectAndValidate(ctx context.Context) error {
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

	if k.params.ClusterName == "" {
		if k.flavor.ClusterName != "" {
			name := strings.ReplaceAll(k.flavor.ClusterName, "_", "-")
			k.Log("🔮 Auto-detected cluster name: %s", name)
			k.params.ClusterName = name
		}
	}

	if k.params.IPAM == "" {
		switch k.flavor.Kind {
		case k8s.KindKind:
			k.params.IPAM = ipamKubernetes
		case k8s.KindEKS:
			k.params.IPAM = ipamENI
		case k8s.KindGKE:
			k.params.IPAM = ipamKubernetes
		case k8s.KindAKS:
			k.params.IPAM = ipamAzure
		default:
			k.params.IPAM = ipamClusterPool
		}

		k.Log("🔮 Auto-detected IPAM mode: %s", k.params.IPAM)
	}

	k.detectDatapathMode(true)

	if strings.Contains(k.params.ClusterName, ".") {
		k.Log("❌ Cluster name %q cannot contain dots", k.params.ClusterName)
		return fmt.Errorf("invalid cluster name, dots are not allowed")
	}

	if !clusterNameValidation.MatchString(k.params.ClusterName) {
		k.Log("❌ Cluster name %q is not valid, must match regular expression: %s", k.params.ClusterName, clusterNameValidation)
		return fmt.Errorf("invalid cluster name")
	}

	switch k.params.Encryption {
	case encryptionDisabled,
		encryptionIPsec,
		encryptionWireguard:
		// nothing to do for valid values
	default:
		k.Log("❌ Invalid encryption mode: %q", k.params.Encryption)
		return fmt.Errorf("invalid encryption mode")
	}

	return nil
}
