// SPDX-License-Identifier: Apache-2.0
// Copyright 2020 Authors of Cilium
// Copyright The Helm Authors.

package install

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/cilium/cilium/pkg/versioncheck"
	"helm.sh/helm/v3/pkg/chart"
	"helm.sh/helm/v3/pkg/chartutil"
	"helm.sh/helm/v3/pkg/cli"
	"helm.sh/helm/v3/pkg/getter"
	"helm.sh/helm/v3/pkg/releaseutil"
	"helm.sh/helm/v3/pkg/strvals"

	"github.com/cilium/cilium-cli/defaults"
	"github.com/cilium/cilium-cli/internal/k8s"
)

var settings = cli.New()

// FilterManifests a map of generated manifests. The Key is the filename and the
// Value is its manifest.
func FilterManifests(manifest string) map[string]string {
	// This is necessary to ensure consistent manifest ordering when using --show-only
	// with globs or directory names.
	var manifests bytes.Buffer
	fmt.Fprintln(&manifests, strings.TrimSpace(manifest))

	splitManifests := releaseutil.SplitManifests(manifests.String())
	manifestsKeys := make([]string, 0, len(splitManifests))
	for k := range splitManifests {
		manifestsKeys = append(manifestsKeys, k)
	}
	sort.Sort(releaseutil.BySplitManifestsOrder(manifestsKeys))

	manifestNameRegex := regexp.MustCompile("# Source: [^/]+/(.+)")

	var (
		manifestsToRender = map[string]string{}
	)

	for _, manifestKey := range manifestsKeys {
		manifest := splitManifests[manifestKey]
		submatch := manifestNameRegex.FindStringSubmatch(manifest)
		if len(submatch) == 0 {
			continue
		}
		manifestName := submatch[1]
		// manifest.Name is rendered using linux-style filepath separators on Windows as
		// well as macOS/linux.
		manifestPathSplit := strings.Split(manifestName, "/")
		// manifest.Path is connected using linux-style filepath separators on Windows as
		// well as macOS/linux
		manifestPath := strings.Join(manifestPathSplit, "/")

		manifestsToRender[manifestPath] = manifest
	}
	return manifestsToRender
}

func (k *K8sInstaller) generateManifests(ctx context.Context) error {
	k8sVersionStr := k.params.K8sVersion
	if k8sVersionStr == "" {
		k8sVersion, err := k.client.GetServerVersion()
		if err != nil {
			return fmt.Errorf("error getting Kubernetes version, try --k8s-version: %s", err)
		}
		k8sVersionStr = k8sVersion.String()
	}

	helmClient, err := newHelmClient(k.params.Namespace, k8sVersionStr)
	if err != nil {
		return err
	}

	ciliumVer := k.getCiliumVersion()

	var helmChart *chart.Chart
	if helmDir := k.params.HelmChartDirectory; helmDir != "" {
		helmChart, err = newHelmChartFromDirectory(helmDir)
		if err != nil {
			return err
		}
	} else {
		helmChart, err = newHelmChartFromCiliumVersion(ciliumVer.String())
		if err != nil {
			return err
		}
	}

	helmMapOpts := map[string]string{}
	switch {
	// It's likely that certain helm options have changed since 1.9.0
	// These were tested for the >=1.11.0. In case something breaks for versions
	// older than 1.11.0 we will fix it afterwards.
	case versioncheck.MustCompile(">=1.9.0")(ciliumVer):
		// case versioncheck.MustCompile(">=1.11.0")(ciliumVer):
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

	// Create helm values from helmMapOpts
	var helmOpts []string
	for k, v := range helmMapOpts {
		if v == "" {
			panic(fmt.Sprintf("empty value form helm option %q", k))
		}
		helmOpts = append(helmOpts, fmt.Sprintf("%s=%s", k, v))
	}

	helmOptsStr := strings.Join(helmOpts, ",")

	ciliumCliHelmValues := map[string]interface{}{}
	err = strvals.ParseInto(helmOptsStr, ciliumCliHelmValues)
	if err != nil {
		return fmt.Errorf("error parsing helm options %q: %w", helmOptsStr, err)
	}

	// Get the user-defined helm options passed by flag
	p := getter.All(settings)
	vals, err := k.params.HelmOpts.MergeValues(p)
	if err != nil {
		return err
	}

	// User-defined helm options will overwrite the default cilium-cli helm options
	vals = mergeMaps(ciliumCliHelmValues, vals)

	valsStr := valuesToString("", vals)

	if helmChartDir := k.params.HelmChartDirectory; helmChartDir != "" {
		k.Log("ℹ️  helm template --namespace %s cilium %q --version %s --set %s", k.params.Namespace, helmChartDir, ciliumVer, valsStr)
	} else {
		k.Log("ℹ️  helm template --namespace %s cilium cilium/cilium --version %s --set %s", k.params.Namespace, ciliumVer, valsStr)
	}

	// Store the current helm-opts used in this installation in Cilium's
	// ConfigMap
	extraConfig := map[string]interface{}{
		"extraConfig": map[string]interface{}{
			defaults.ExtraConfigMapUserOptsKey: valsStr,
		},
	}

	// User-defined helm options will overwrite the default cilium-cli helm options
	vals = mergeMaps(extraConfig, vals)

	rel, err := helmClient.RunWithContext(ctx, helmChart, vals)
	if err != nil {
		return err
	}

	if k.params.HelmGenValuesFile != "" {
		yamlValue, err := chartutil.Values(vals).YAML()
		if err != nil {
			return err
		}
		return os.WriteFile(k.params.HelmGenValuesFile, []byte(yamlValue), 0o600)
	}

	k.manifests = FilterManifests(rel.Manifest)
	return nil
}

func mergeMaps(a, b map[string]interface{}) map[string]interface{} {
	out := make(map[string]interface{}, len(a))
	for k, v := range a {
		out[k] = v
	}
	for k, v := range b {
		if v, ok := v.(map[string]interface{}); ok {
			if bv, ok := out[k]; ok {
				if bv, ok := bv.(map[string]interface{}); ok {
					out[k] = mergeMaps(bv, v)
					continue
				}
			}
		}
		out[k] = v
	}
	return out
}

func valuesToString(prevKey string, b map[string]interface{}) string {
	var out []string
	for k, v := range b {
		if v, ok := v.(map[string]interface{}); ok {
			if prevKey != "" {
				out = append(out, valuesToString(fmt.Sprintf("%s.%s", prevKey, k), v))
			} else {
				out = append(out, valuesToString(k, v))
			}
			continue
		}
		if prevKey != "" {
			out = append(out, fmt.Sprintf("%s.%s=%v", prevKey, k, v))
		} else {
			out = append(out, fmt.Sprintf("%s=%v", k, v))
		}
	}
	sort.Strings(out)
	return strings.Join(out, ",")
}
