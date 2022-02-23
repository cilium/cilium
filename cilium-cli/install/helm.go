// SPDX-License-Identifier: Apache-2.0
// Copyright 2020 Authors of Cilium
// Copyright The Helm Authors.

package install

import (
	"bytes"
	"context"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/cilium/cilium/pkg/versioncheck"
	"helm.sh/helm/v3/pkg/chart"
	"helm.sh/helm/v3/pkg/releaseutil"
	"helm.sh/helm/v3/pkg/strvals"

	"github.com/cilium/cilium-cli/defaults"
	"github.com/cilium/cilium-cli/internal/k8s"
)

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

		if k.params.Encryption == encryptionIPsec {
			helmMapOpts["encryption.enabled"] = "true"
			helmMapOpts["encryption.type"] = "ipsec"
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
		case DatapathAwsENI:
			helmMapOpts["eni.enabled"] = "true"
			helmMapOpts["nodeinit.enabled"] = "true"

		case DatapathAzure:
			helmMapOpts["azure.enabled"] = "true"
			helmMapOpts["azure.subscriptionID"] = k.params.Azure.SubscriptionID
			helmMapOpts["azure.tenantID"] = k.params.Azure.TenantID
			helmMapOpts["azure.resourceGroup"] = k.params.Azure.AKSNodeResourceGroup
		}

		if k.bgpEnabled() {
			helmMapOpts["bgp.enabled"] = "true"
		}

	default:
		return fmt.Errorf("cilium version unsupported %s", ciliumVer.String())
	}

	var helmOpts []string
	for k, v := range helmMapOpts {
		if v == "" {
			panic(fmt.Sprintf("empty value form helm option %q", k))
		}
		helmOpts = append(helmOpts, fmt.Sprintf("%s=%s", k, v))
	}

	sort.Strings(helmOpts)
	helmOptsStr := strings.Join(helmOpts, ",")

	helmValues := map[string]interface{}{}
	err = strvals.ParseInto(helmOptsStr, helmValues)
	if err != nil {
		return fmt.Errorf("error parsing helm options %q: %w", helmOptsStr, err)
	}

	if helmChartDir := k.params.HelmChartDirectory; helmChartDir != "" {
		k.Log("ℹ️  helm template --namespace %s cilium %q --version %s --set %s", k.params.Namespace, helmChartDir, ciliumVer, helmOptsStr)
	} else {
		k.Log("ℹ️  helm template --namespace %s cilium cilium/cilium --version %s --set %s", k.params.Namespace, ciliumVer, helmOptsStr)
	}

	rel, err := helmClient.RunWithContext(ctx, helmChart, helmValues)
	if err != nil {
		return err
	}

	k.manifests = FilterManifests(rel.Manifest)
	return nil
}
