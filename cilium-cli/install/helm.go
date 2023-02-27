// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium
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
	helmMapOpts := map[string]string{}
	deprecatedCfgOpts := map[string]string{}

	switch {
	// It's likely that certain helm options have changed since 1.9.0
	// These were tested for the >=1.11.0. In case something breaks for versions
	// older than 1.11.0 we will fix it afterwards.
	case versioncheck.MustCompile(">=1.9.0")(k.chartVersion):
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

		imageSuffix := k.params.ImageSuffix
		if imageSuffix != "" {
			// When using suffix tag must be defaulted to "latest" to prevent deduced
			// version from being used as the operator tag by Cilium Helm charts.
			// This also makes k8s pod list to actually contain the image tag.
			if imageTag == "" {
				imageTag = "latest"
				k.Log("ℹ️  Defaulting image tag to %q due to --image-suffix option", imageTag)
			}
			colonTag := ":" + imageTag
			helmMapOpts["image.override"] = fmt.Sprintf("quay.io/cilium/cilium%s%s", imageSuffix, colonTag)
			helmMapOpts["image.useDigest"] = "false"
			// operator has different cloud variants and supports image.suffix
			helmMapOpts["operator.image.suffix"] = imageSuffix
			helmMapOpts["operator.image.tag"] = imageTag
			helmMapOpts["operator.image.useDigest"] = "false"
			helmMapOpts["hubble.relay.image.override"] = fmt.Sprintf("quay.io/cilium/hubble-relay%s%s", imageSuffix, colonTag)
			helmMapOpts["hubble.relay.image.useDigest"] = "false"
			helmMapOpts["preflight.image.override"] = fmt.Sprintf("quay.io/cilium/cilium%s%s", imageSuffix, colonTag)
			helmMapOpts["preflight.image.useDigest"] = "false"
			helmMapOpts["clustermesh.apiserver.image.override"] = fmt.Sprintf("quay.io/cilium/clustermesh-apiserver%s%s", imageSuffix, colonTag)
			helmMapOpts["clustermesh.apiserver.image.useDigest"] = "false"
		} else if imageTag != "" {
			// Helm ignores image.tag if image.override is set
			helmMapOpts["image.tag"] = imageTag
			helmMapOpts["image.useDigest"] = "false"
			helmMapOpts["operator.image.tag"] = imageTag
			helmMapOpts["operator.image.useDigest"] = "false"
			helmMapOpts["hubble.relay.image.tag"] = imageTag
			helmMapOpts["hubble.relay.image.useDigest"] = "false"
			helmMapOpts["preflight.image.tag"] = imageTag
			helmMapOpts["preflight.image.useDigest"] = "false"
			helmMapOpts["clustermesh.apiserver.image.tag"] = imageTag
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

		switch k.params.Encryption {
		case encryptionIPsec:
			helmMapOpts["encryption.enabled"] = "true"
			helmMapOpts["encryption.type"] = "ipsec"
			if k.params.NodeEncryption {
				helmMapOpts["encryption.nodeEncryption"] = "true"
			}
		case encryptionWireguard:
			helmMapOpts["encryption.enabled"] = "true"
			helmMapOpts["encryption.type"] = "wireguard"
			// TODO(gandro): Future versions of Cilium will remove the following
			// two limitations, we will need to have set the config map values
			// based on the installed Cilium version
			if versioncheck.MustCompile("<=1.13.0")(k.chartVersion) {
				helmMapOpts["l7Proxy"] = "false"
				k.Log("ℹ️  L7 proxy disabled due to Wireguard encryption")

				if k.params.NodeEncryption {
					k.Log("⚠️️  Wireguard does not support node encryption yet")
				}
			}
		}

		// Set Helm options specific to the detected Kubernetes cluster type
		switch k.flavor.Kind {
		case k8s.KindKind:
			helmMapOpts["ipam.mode"] = ipamKubernetes

		case k8s.KindEKS:
			helmMapOpts["nodeinit.enabled"] = "true"

		case k8s.KindGKE:
			helmMapOpts["nodeinit.enabled"] = "true"
			helmMapOpts["nodeinit.removeCbrBridge"] = "true"
			helmMapOpts["nodeinit.reconfigureKubelet"] = "true"
			helmMapOpts["cni.binPath"] = "/home/kubernetes/bin"

		case k8s.KindAKS:
			helmMapOpts["nodeinit.enabled"] = "true"

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
			helmMapOpts["tunnel"] = tunnelVxlan

		case DatapathAwsENI:
			helmMapOpts["ipam.mode"] = ipamENI
			helmMapOpts["eni.enabled"] = "true"
			helmMapOpts["tunnel"] = tunnelDisabled
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
			helmMapOpts["tunnel"] = tunnelDisabled
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

		// TODO: remove when removing "cluster-id" flag (marked as deprecated), kept
		// for backwards compatibility
		if k.params.ClusterID != 0 {
			helmMapOpts["cluster.id"] = strconv.FormatInt(int64(k.params.ClusterID), 10)
		}

		// TODO: remove when removing "ipam" flag (marked as deprecated), kept for
		// backwards compatibility
		if k.params.IPAM != "" {
			helmMapOpts["ipam.mode"] = k.params.IPAM
		}

		// TODO: remove when removing "kube-proxy-replacement" flag (marked as
		// deprecated), kept for backwards compatibility
		if k.params.KubeProxyReplacement != "" && k.params.UserSetKubeProxyReplacement {
			helmMapOpts["kubeProxyReplacement"] = k.params.KubeProxyReplacement
		}

		// TODO: remove when removing "config" flag (marked as deprecated), kept
		// for backwards compatibility
		if k.bgpEnabled() {
			helmMapOpts["bgp.enabled"] = "true"
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
		return fmt.Errorf("cilium version unsupported %s", k.chartVersion)
	}

	// Set affinity to prevent Cilium from being scheduled on nodes labeled with
	// "cilium.io/no-schedule=true"
	if len(k.params.NodesWithoutCilium) != 0 {
		for k, v := range defaults.CiliumScheduleAffinity {
			helmMapOpts[k] = v
		}
	}

	// Store all the options passed by --config into helm extraConfig
	extraConfigMap := map[string]interface{}{}
	for k, v := range deprecatedCfgOpts {
		extraConfigMap[k] = v
	}

	vals, err := helm.MergeVals(k.params.HelmOpts, helmMapOpts, nil, extraConfigMap)
	if err != nil {
		return err
	}

	// Pull APIVersions and filter for known needed CRDs, if not provided by the user.
	// _Each value_ in apiVersions passed to helm.MergeVals will be logged in the `helm template` command, so
	// pulling all values from the API server will add a ton of '--api-versions <group/version>' arguments to
	// the printed command if filtering is not performed.
	// Filtering reduces this output to a reasonable size for users, and works for now since there is a limited
	// set of CRDs needed for helm template verification.
	apiVersions := k.params.APIVersions
	if len(apiVersions) == 0 {
		gvs, err := k.client.ListAPIResources(ctx)
		if err != nil {
			k.Log("⚠️ Unable to list kubernetes api resources, try --api-versions if needed: %w", err)
		}
		for _, gv := range gvs {
			switch gv {
			case "monitoring.coreos.com/v1":
				apiVersions = append(apiVersions, gv)
			}
		}
	}

	helm.PrintHelmTemplateCommand(k, vals, k.params.HelmChartDirectory, k.params.Namespace, k.chartVersion, apiVersions)

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

	manifests, err := helm.GenManifests(ctx, k.params.HelmChartDirectory, k8sVersionStr, k.chartVersion, k.params.Namespace, vals, apiVersions)
	if err != nil {
		return err
	}

	k.manifests = manifests
	k.helmYAMLValues = yamlValue
	return nil
}
