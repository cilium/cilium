// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

// Copyright The Helm Authors.

package install

import (
	"fmt"

	"github.com/cilium/cilium-cli/defaults"
	"github.com/cilium/cilium-cli/internal/helm"
	"github.com/cilium/cilium-cli/k8s"

	"github.com/cilium/cilium/pkg/versioncheck"
)

func (k *K8sInstaller) getHelmValues() (map[string]interface{}, error) {
	helmMapOpts := map[string]string{}
	deprecatedCfgOpts := map[string]string{}

	switch {
	// It's likely that certain helm options have changed since 1.9.0
	// These were tested for the >=1.11.0. In case something breaks for versions
	// older than 1.11.0 we will fix it afterwards.
	case versioncheck.MustCompile(">=1.9.0")(k.chartVersion):
		// TODO(aanm) to keep the previous behavior unchanged we will set the number
		// of the operator replicas to 1. Ideally this should be the default in the helm chart
		helmMapOpts["operator.replicas"] = "1"

		// Set nodeinit enabled option
		if needsNodeInit(k.flavor.Kind, k.chartVersion) {
			helmMapOpts["nodeinit.enabled"] = "true"
		}

		// Set Helm options specific to the detected Kubernetes cluster type
		switch k.flavor.Kind {
		case k8s.KindKind:
			helmMapOpts["ipam.mode"] = ipamKubernetes

		case k8s.KindGKE:
			helmMapOpts["nodeinit.removeCbrBridge"] = "true"
			helmMapOpts["nodeinit.reconfigureKubelet"] = "true"
			helmMapOpts["cni.binPath"] = "/home/kubernetes/bin"

		case k8s.KindMicrok8s:
			helmMapOpts["cni.binPath"] = Microk8sSnapPath + "/opt/cni/bin"
			helmMapOpts["cni.confPath"] = Microk8sSnapPath + "/args/cni-network"
			helmMapOpts["daemon.runPath"] = Microk8sSnapPath + "/var/run/cilium"

		case k8s.KindRancherDesktop:
			helmMapOpts["cni.binPath"] = "/usr/libexec/cni"
		}

		// Set Helm options specific to the detected / selected datapath mode
		switch k.params.DatapathMode {
		case DatapathTunnel:
			if versioncheck.MustCompile(">=1.14.0")(k.chartVersion) {
				helmMapOpts["routingMode"] = routingModeTunnel
				helmMapOpts["tunnelProtocol"] = tunnelVxlan
			} else {
				helmMapOpts["tunnel"] = tunnelVxlan
			}
		case DatapathAwsENI:
			helmMapOpts["ipam.mode"] = ipamENI
			helmMapOpts["eni.enabled"] = "true"
			if versioncheck.MustCompile(">=1.14.0")(k.chartVersion) {
				helmMapOpts["routingMode"] = routingModeNative
			} else {
				// Can be removed once we drop support for <1.14.0
				helmMapOpts["tunnel"] = tunnelDisabled
			}
			// TODO(tgraf) Is this really sane?
			helmMapOpts["egressMasqueradeInterfaces"] = "eth0"

		case DatapathGKE:
			helmMapOpts["ipam.mode"] = ipamKubernetes
			helmMapOpts["gke.enabled"] = "true"
			helmMapOpts["gke.disableDefaultSnat"] = "true"

		case DatapathAzure:
			helmMapOpts["ipam.mode"] = ipamAzure
			helmMapOpts["azure.enabled"] = "true"
			helmMapOpts["azure.subscriptionID"] = k.params.Azure.SubscriptionID
			helmMapOpts["azure.resourceGroup"] = k.params.Azure.AKSNodeResourceGroup
			helmMapOpts["azure.tenantID"] = k.params.Azure.TenantID
			helmMapOpts["azure.clientID"] = k.params.Azure.ClientID
			helmMapOpts["azure.clientSecret"] = k.params.Azure.ClientSecret
			if versioncheck.MustCompile(">=1.14.0")(k.chartVersion) {
				helmMapOpts["routingMode"] = routingModeNative
			} else {
				// Can be removed once we drop support for <1.14.0
				helmMapOpts["tunnel"] = tunnelDisabled
			}
			switch {
			case versioncheck.MustCompile(">=1.10.0")(k.chartVersion):
				helmMapOpts["bpf.masquerade"] = "false"
				helmMapOpts["enableIPv4Masquerade"] = "false"
				helmMapOpts["enableIPv6Masquerade"] = "false"
			case versioncheck.MustCompile(">=1.9.0")(k.chartVersion):
				helmMapOpts["masquerade"] = "false"
			}

		case DatapathAKSBYOCNI:
			switch {
			case versioncheck.MustCompile(">=1.12.0")(k.chartVersion):
				helmMapOpts["aksbyocni.enabled"] = "true"
			case versioncheck.MustCompile(">=1.9.0")(k.chartVersion):
				// Manually configure the same ConfigMap options as the new
				// `aksbyocni` mode does, so that it works transparently.
				helmMapOpts["ipam.mode"] = ipamClusterPool
				helmMapOpts["tunnel"] = tunnelVxlan
			}
		}

		// TODO: remove when removing "cluster-name" flag (marked as deprecated),
		// kept for backwards compatibility
		if k.params.ClusterName != "" {
			helmMapOpts["cluster.name"] = k.params.ClusterName
		}

		// TODO: remove when removing "ipv4-native-routing-cidr" flag (marked as
		// deprecated), kept for backwards compatibility
		if k.params.IPv4NativeRoutingCIDR != "" {
			// NOTE: Cilium v1.11 replaced --native-routing-cidr by
			// --ipv4-native-routing-cidr
			switch {
			case versioncheck.MustCompile(">=1.11.0")(k.chartVersion):
				helmMapOpts["ipv4NativeRoutingCIDR"] = k.params.IPv4NativeRoutingCIDR
			case versioncheck.MustCompile(">=1.9.0")(k.chartVersion):
				helmMapOpts["nativeRoutingCIDR"] = k.params.IPv4NativeRoutingCIDR
			}
		}

	default:
		return nil, fmt.Errorf("cilium version unsupported %s", k.chartVersion)
	}

	// Set affinity to prevent Cilium from being scheduled on nodes labeled with
	// "cilium.io/no-schedule=true"
	if len(k.params.NodesWithoutCilium) != 0 {
		k.params.HelmOpts.StringValues = append(k.params.HelmOpts.StringValues, defaults.CiliumScheduleAffinity...)
		k.params.HelmOpts.StringValues = append(k.params.HelmOpts.StringValues, defaults.CiliumOperatorScheduleAffinity...)
		k.params.HelmOpts.StringValues = append(k.params.HelmOpts.StringValues, defaults.SpireAgentScheduleAffinity...)
	}

	// Store all the options passed by --config into helm extraConfig
	extraConfigMap := map[string]interface{}{}
	for k, v := range deprecatedCfgOpts {
		extraConfigMap[k] = v
	}

	return helm.MergeVals(k.params.HelmOpts, helmMapOpts, nil, extraConfigMap)
}
