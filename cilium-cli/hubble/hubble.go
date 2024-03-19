// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package hubble

import (
	"context"
	"fmt"
	"io"

	"github.com/cilium/cilium-cli/internal/helm"
	"github.com/cilium/cilium-cli/k8s"

	"helm.sh/helm/v3/pkg/cli/values"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type k8sHubbleImplementation interface {
	GetService(ctx context.Context, namespace, name string, opts metav1.GetOptions) (*corev1.Service, error)
}

type Parameters struct {
	Namespace     string
	Relay         bool
	PortForward   int
	UI            bool
	UIPortForward int
	Writer        io.Writer
	Context       string // Only for 'kubectl' pass-through commands

	// UIOpenBrowser will automatically open browser if true
	UIOpenBrowser bool

	// Wait will cause Helm upgrades related to disabling Hubble to wait.
	Wait bool

	HelmReleaseName string
}

func (p *Parameters) Log(format string, a ...interface{}) {
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
		Namespace:   params.Namespace,
		Name:        params.HelmReleaseName,
		Values:      vals,
		ResetValues: false,
		ReuseValues: true,
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
		Namespace:   params.Namespace,
		Name:        params.HelmReleaseName,
		Values:      vals,
		ResetValues: false,
		ReuseValues: true,
		Wait:        params.Wait,
	}
	_, err = helm.Upgrade(ctx, k8sClient.HelmActionConfig, upgradeParams)
	return err
}
