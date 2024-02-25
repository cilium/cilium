// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package install

import (
	"context"
	"fmt"

	"helm.sh/helm/v3/pkg/cli"
	"helm.sh/helm/v3/pkg/getter"
	"sigs.k8s.io/yaml"

	"github.com/cilium/cilium-cli/defaults"
	"github.com/cilium/cilium-cli/internal/helm"
	"github.com/cilium/cilium-cli/k8s"
)

func (k *K8sInstaller) UpgradeWithHelm(ctx context.Context, k8sClient *k8s.Client) error {
	if k.params.ListVersions {
		return k.listVersions()
	}
	if err := k.preinstall(ctx); err != nil {
		return err
	}

	vals, err := k.params.HelmOpts.MergeValues(getter.All(cli.New()))
	if err != nil {
		return err
	}

	upgradeParams := helm.UpgradeParameters{
		Namespace:    k.params.Namespace,
		Name:         defaults.HelmReleaseName,
		Chart:        k.chart, // k.chart was initialized in NewK8sInstaller, based on Version and HelmChartDirectory
		Values:       vals,
		ResetValues:  k.params.HelmResetValues,
		ReuseValues:  k.params.HelmReuseValues,
		Wait:         k.params.Wait,
		WaitDuration: k.params.WaitDuration,

		// In addition to the DryRun i/o, we need to tell Helm not to execute the upgrade
		DryRun:           k.params.DryRun,
		DryRunHelmValues: k.params.DryRunHelmValues,
	}
	release, err := helm.Upgrade(ctx, k8sClient.HelmActionConfig, upgradeParams)
	if err != nil {
		return err
	}

	if k.params.DryRun {
		fmt.Println(release.Manifest)
	}
	if k.params.DryRunHelmValues {
		helmValues, err := yaml.Marshal(release.Config)
		if err != nil {
			return err
		}
		fmt.Println(string(helmValues))
	}

	return err
}
