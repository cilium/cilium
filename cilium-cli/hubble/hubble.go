// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package hubble

import (
	"context"
	"fmt"
	"io"

	"helm.sh/helm/v4/pkg/cli/values"

	"github.com/cilium/cilium/cilium-cli/defaults"
	"github.com/cilium/cilium/cilium-cli/internal/helm"
	"github.com/cilium/cilium/cilium-cli/k8s"
)

type Parameters struct {
	Namespace     string
	Relay         bool
	PortForward   int
	UI            bool
	UIPortForward int
	Writer        io.Writer

	// UIOpenBrowser will automatically open browser if true
	UIOpenBrowser bool

	// Wait will cause Helm upgrades related to disabling Hubble to wait.
	Wait bool

	HelmReleaseName string
}

func (p *Parameters) Log(format string, a ...any) {
	fmt.Fprintf(p.Writer, format+"\n", a...)
}

func EnableWithHelm(ctx context.Context, k8sClient *k8s.Client, params Parameters) error {
	options := values.Options{
		Values: []string{
			fmt.Sprintf("hubble.relay.enabled=%t", params.Relay),
			fmt.Sprintf("hubble.ui.enabled=%t", params.UI),
		},
	}
	vals, err := helm.MergeVals(options, nil)
	if err != nil {
		return err
	}
	upgradeParams := helm.UpgradeParameters{
		Namespace:    params.Namespace,
		Name:         params.HelmReleaseName,
		Values:       vals,
		ResetValues:  false,
		ReuseValues:  true,
		WaitDuration: defaults.UninstallTimeout,
	}
	_, err = helm.Upgrade(ctx, k8sClient.HelmActionConfig, upgradeParams)
	return err
}

func DisableWithHelm(ctx context.Context, k8sClient *k8s.Client, params Parameters) error {
	options := values.Options{
		Values: []string{"hubble.relay.enabled=false", "hubble.ui.enabled=false"},
	}
	vals, err := helm.MergeVals(options, nil)
	if err != nil {
		return err
	}
	upgradeParams := helm.UpgradeParameters{
		Namespace:    params.Namespace,
		Name:         params.HelmReleaseName,
		Values:       vals,
		ResetValues:  false,
		ReuseValues:  true,
		Wait:         params.Wait,
		WaitDuration: defaults.UninstallTimeout,
	}
	_, err = helm.Upgrade(ctx, k8sClient.HelmActionConfig, upgradeParams)
	return err
}
