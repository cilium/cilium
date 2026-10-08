// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package bgp

import (
	"github.com/cilium/hive/cell"
	"k8s.io/client-go/util/workqueue"

	"github.com/cilium/cilium/pkg/bgp/config"
	"github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slim_core_v1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	"github.com/cilium/cilium/pkg/k8s/utils"
	"github.com/cilium/cilium/pkg/metrics"
)

var Cell = cell.Module(
	"bgp-cp-operator",
	"BGP Control Plane Operator",

	cell.Config(config.DefaultConfig),

	cell.ProvidePrivate(newSecretResource),
	cell.Invoke(registerBGPResourceManager),
	cell.Invoke(registerPeerConfigStatusReconciler),
	metrics.Metric(NewBGPOperatorMetrics),
)

func newSecretResource(lc cell.Lifecycle, c client.Clientset, bc config.BGPConfig, mp workqueue.MetricsProvider) resource.Resource[*slim_core_v1.Secret] {
	// Secret is only used for status reporting (MissingAuthSecret condition)
	if !c.IsEnabled() || !bc.BGPControlPlaneEnabled() || !bc.EnableStatusReport {
		return nil
	}
	if bc.SecretsNamespace == "" {
		return nil
	}
	return resource.New[*slim_core_v1.Secret](
		lc, utils.ListerWatcherFromTyped[*slim_core_v1.SecretList](
			c.Slim().CoreV1().Secrets(bc.SecretsNamespace),
		), mp)
}
