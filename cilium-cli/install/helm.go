// SPDX-License-Identifier: Apache-2.0
// Copyright 2020 Authors of Cilium
// Copyright The Helm Authors.

package install

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/cilium/cilium-cli/defaults"
	"github.com/cilium/cilium-cli/internal/helm"
	"github.com/cilium/cilium-cli/k8s"

	"github.com/cilium/cilium/pkg/versioncheck"
	"github.com/spf13/pflag"
	"helm.sh/helm/v3/pkg/chartutil"
)

func (k *K8sInstaller) generateManifests(ctx context.Context) error {
	ciliumVer := k.getCiliumVersion()

	helmMapOpts := map[string]string{}
	deprecatedCfgOpts := map[string]string{}

	switch {
	// It's likely that certain helm options have changed since 1.9.0
	// These were tested for the >=1.11.0. In case something breaks for versions
	// older than 1.11.0 we will fix it afterwards.
	case versioncheck.MustCompile(">=1.9.0")(ciliumVer):
		// case versioncheck.MustCompile(">=1.11.0")(ciliumVer):
		// If the user has specified a version with `--image-tag` then
		// set all image tags with that version. The user will have the
		// option to overwrite any of these options with the specific
		// helm option.
		imageTag := k.params.ImageTag
		if imageTag == "" {
			// If the user has specified a version with `--version` then
			// set all image tags with that version. The user will have the
			// option to overwrite any of these options with the specific
			// helm option.
			imageTag = k.getImagesSHA()
		}

		if imageTag != "" {
			helmMapOpts["image.tag"] = imageTag
			helmMapOpts["image.useDigest"] = "false"
			helmMapOpts["operator.image.tag"] = imageTag
			helmMapOpts["operator.image.digest"] = "false"
			helmMapOpts["hubble.relay.image.tag"] = imageTag
			helmMapOpts["hubble.relay.image.useDigest"] = "false"
			helmMapOpts["preflight.image.tag"] = imageTag
			helmMapOpts["preflight.image.useDigest"] = "false"
			helmMapOpts["clustermesh.apiserver.image.tag"] = imageTag
			helmMapOpts["clustermesh.apiserver.image.useDigest"] = "false"
		}

		imageSuffix := k.params.ImageSuffix
		if imageSuffix != "" {
			helmMapOpts["image.override"] = fmt.Sprintf("quay.io/cilium/cilium%s", imageSuffix)
			helmMapOpts["image.useDigest"] = "false"
			helmMapOpts["operator.image.suffix"] = imageSuffix
			helmMapOpts["operator.image.digest"] = "false"
			helmMapOpts["hubble.relay.image.override"] = fmt.Sprintf("quay.io/cilium/hubble-relay%s", imageSuffix)
			helmMapOpts["hubble.relay.image.useDigest"] = "false"
			helmMapOpts["preflight.image.override"] = fmt.Sprintf("quay.io/cilium/cilium%s", imageSuffix)
			helmMapOpts["preflight.image.useDigest"] = "false"
			helmMapOpts["clustermesh.apiserver.image.override"] = fmt.Sprintf("quay.io/cilium/clustermesh-apiserver%s", imageSuffix)
			helmMapOpts["clustermesh.apiserver.image.useDigest"] = "false"
		}

		// Pre-define all deprecated flags as helm options
		for flagName, helmOpt := range FlagsToHelmOpts {
			if v, ok := FlagValues[flagName]; ok {
				if val := v.String(); val != "" {
					helmMapOpts[helmOpt] = val
				}
			}
		}
		// Handle the "config" values in a special way since they are a
		// stringSlice
		if v, ok := FlagValues["config"]; ok {
			switch sv := v.(type) {
			case pflag.SliceValue:
				for _, cfgOpt := range sv.GetSlice() {
					cfgOptSplit := strings.Split(cfgOpt, "=")
					if len(cfgOptSplit) != 2 {
						return fmt.Errorf("--config should be in the format of <key=value>, got %s", cfgOpt)
					}
					deprecatedCfgOpts[cfgOptSplit[0]] = cfgOptSplit[1]
				}

			default:
				panic("Config should be type pflag.SliceValue")
			}
		}

		helmMapOpts["serviceAccounts.cilium.name"] = defaults.AgentServiceAccountName
		helmMapOpts["serviceAccounts.operator.name"] = defaults.OperatorServiceAccountName

		// TODO(aanm) to keep the previous behavior unchanged we will set the number
		// of the operator replicas to 1. Ideally this should be the default in the helm chart
		helmMapOpts["operator.replicas"] = "1"

		if k.params.ClusterName != "" {
			helmMapOpts["cluster.name"] = k.params.ClusterName
		}

		if k.params.ClusterID != 0 {
			helmMapOpts["cluster.id"] = strconv.FormatInt(int64(k.params.ClusterID), 10)
		}

		switch k.params.Encryption {
		case encryptionIPsec:
			helmMapOpts["encryption.enabled"] = "true"
			helmMapOpts["encryption.type"] = "ipsec"
			if k.params.NodeEncryption {
				helmMapOpts["encryption.nodeEncryption"] = "true"
			}
		case encryptionWireguard:
			helmMapOpts["encryption.type"] = "wireguard"
			// TODO(gandro): Future versions of Cilium will remove the following
			// two limitations, we will need to have set the config map values
			// based on the installed Cilium version
			helmMapOpts["l7Proxy"] = "false"
			k.Log("ℹ️  L7 proxy disabled due to Wireguard encryption")

			if k.params.NodeEncryption {
				k.Log("⚠️️  Wireguard does not support node encryption yet")
			}
		}

		if k.params.IPAM != "" {
			helmMapOpts["ipam.mode"] = k.params.IPAM
		}

		if k.params.ClusterID != 0 {
			helmMapOpts["cluster.id"] = fmt.Sprintf("%d", k.params.ClusterID)
		}

		if k.params.KubeProxyReplacement != "" {
			helmMapOpts["kubeProxyReplacement"] = k.params.KubeProxyReplacement
		}

		switch k.flavor.Kind {
		case k8s.KindGKE:
			helmMapOpts["gke.enabled"] = "true"
			helmMapOpts["gke.disableDefaultSnat"] = "true"
			helmMapOpts["nodeinit.enabled"] = "true"
			helmMapOpts["nodeinit.removeCbrBridge"] = "true"
			helmMapOpts["nodeinit.reconfigureKubelet"] = "true"
			helmMapOpts["cni.binPath"] = "/home/kubernetes/bin"

		case k8s.KindMicrok8s:
			helmMapOpts["cni.binPath"] = Microk8sSnapPath + "/opt/cni/bin"
			helmMapOpts["cni.confPath"] = Microk8sSnapPath + "/args/cni-network"
			helmMapOpts["daemon.runPath"] = Microk8sSnapPath + "/var/run/cilium"

		case k8s.KindRancherDesktop:
			helmMapOpts["cni.binPath"] = "/usr/libexec/cni"

		case k8s.KindAKS:
			helmMapOpts["nodeinit.enabled"] = "true"
			helmMapOpts["azure.enabled"] = "true"
			helmMapOpts["azure.clientID"] = k.params.Azure.ClientID
			helmMapOpts["azure.clientSecret"] = k.params.Azure.ClientSecret

		case k8s.KindEKS:
			helmMapOpts["nodeinit.enabled"] = "true"
		}

		switch k.params.DatapathMode {
		case DatapathTunnel:
			t := k.params.TunnelType
			if t == "" {
				t = defaults.TunnelType
			}
			helmMapOpts["tunnel"] = t

		case DatapathAwsENI:
			helmMapOpts["nodeinit.enabled"] = "true"
			helmMapOpts["tunnel"] = "disabled"
			helmMapOpts["eni.enabled"] = "true"
			// TODO(tgraf) Is this really sane?
			helmMapOpts["egressMasqueradeInterfaces"] = "eth0"

		case DatapathGKE:
			helmMapOpts["gke.enabled"] = "true"

		case DatapathAzure:
			helmMapOpts["azure.enabled"] = "true"
			helmMapOpts["tunnel"] = "disabled"
			switch {
			case versioncheck.MustCompile(">=1.10.0")(ciliumVer):
				helmMapOpts["bpf.masquerade"] = "false"
				helmMapOpts["enableIPv4Masquerade"] = "false"
				helmMapOpts["enableIPv6Masquerade"] = "false"
			case versioncheck.MustCompile(">=1.9.0")(ciliumVer):
				helmMapOpts["masquerade"] = "false"
			}
			helmMapOpts["azure.subscriptionID"] = k.params.Azure.SubscriptionID
			helmMapOpts["azure.tenantID"] = k.params.Azure.TenantID
			helmMapOpts["azure.resourceGroup"] = k.params.Azure.AKSNodeResourceGroup
		}

		if k.bgpEnabled() {
			helmMapOpts["bgp.enabled"] = "true"
		}

		if k.params.IPv4NativeRoutingCIDR != "" {
			// NOTE: Cilium v1.11 replaced --native-routing-cidr by
			// --ipv4-native-routing-cidr
			switch {
			case versioncheck.MustCompile(">=1.11.0")(ciliumVer):
				helmMapOpts["ipv4NativeRoutingCIDR"] = k.params.IPv4NativeRoutingCIDR
			case versioncheck.MustCompile(">=1.9.0")(ciliumVer):
				helmMapOpts["nativeRoutingCIDR"] = k.params.IPv4NativeRoutingCIDR
			}
		}

	default:
		return fmt.Errorf("cilium version unsupported %s", ciliumVer.String())
	}

	// Store all the options passed by --config into helm extraConfig
	extraConfigMap := map[string]interface{}{}
	for k, v := range deprecatedCfgOpts {
		extraConfigMap[k] = v
	}

	vals, err := helm.MergeVals(k, true, k.params.HelmOpts, helmMapOpts, nil, extraConfigMap, k.params.HelmChartDirectory, ciliumVer.String(), k.params.Namespace)
	if err != nil {
		return err
	}

	yamlValue, err := chartutil.Values(vals).YAML()
	if err != nil {
		return err
	}

	if k.params.HelmGenValuesFile != "" {
		return os.WriteFile(k.params.HelmGenValuesFile, []byte(yamlValue), 0o600)
	}

	k8sVersionStr := k.params.K8sVersion
	if k8sVersionStr == "" {
		k8sVersion, err := k.client.GetServerVersion()
		if err != nil {
			return fmt.Errorf("error getting Kubernetes version, try --k8s-version: %s", err)
		}
		k8sVersionStr = k8sVersion.String()
	}

	manifests, err := helm.GenManifests(ctx, k.params.HelmChartDirectory, k8sVersionStr, ciliumVer.String(), k.params.Namespace, vals)
	if err != nil {
		return err
	}

	k.manifests = manifests
	k.helmYAMLValues = yamlValue
	return nil
}
