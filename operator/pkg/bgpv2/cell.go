// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package bgpv2

import (
	"github.com/cilium/hive/cell"

	"github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slim_core_v1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	"github.com/cilium/cilium/pkg/k8s/utils"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/option"
)

var Cell = cell.Module(
	"bgp-cp-operator",
	"BGP Control Plane Operator",
	cell.ProvidePrivate(newSecretResource),
	cell.Invoke(registerBGPResourceManager),
	cell.Invoke(registerPeerConfigStatusReconciler),
	metrics.Metric(NewBGPOperatorMetrics),
)

func newSecretResource(lc cell.Lifecycle, c client.Clientset, dc *option.DaemonConfig) resource.Resource[*slim_core_v1.Secret] {
	// Secret is only used for status reporting (MissingAuthSecret condition)
	if !c.IsEnabled() || !dc.BGPControlPlaneEnabled() || !dc.EnableBGPControlPlaneStatusReport {
		return nil
	}
	if dc.BGPSecretsNamespace == "" {
		return nil
	}
	return resource.New[*slim_core_v1.Secret](
		lc, utils.ListerWatcherFromTyped[*slim_core_v1.SecretList](
			c.Slim().CoreV1().Secrets(dc.BGPSecretsNamespace),
		))
}
