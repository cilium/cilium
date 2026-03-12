// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package config

import (
	"github.com/cilium/hive/cell"
	"k8s.io/client-go/util/workqueue"

	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	client "github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/k8s/utils"
	"github.com/cilium/cilium/pkg/option"
)

// Cell provides the Network Driver Config controller which reconciles
// CiliumNetworkDriverClusterConfig resources into CiliumNetworkDriverNodeConfig
// resources based on node label selectors.
var Cell = cell.Module(
	"networkdriverconfig",
	"Network Driver Config Controller",

	cell.ProvidePrivate(
		ciliumNetworkDriverClusterConfig,
		ciliumNetworkDriverNodeConfig,
	),
)

// ciliumNetworkDriverClusterConfig creates a Resource for watching
// CiliumNetworkDriverClusterConfig custom resources. Returns nil if the
// Kubernetes clientset is not enabled, allowing graceful degradation.
func ciliumNetworkDriverClusterConfig(
	lc cell.Lifecycle,
	cs client.Clientset,
	mp workqueue.MetricsProvider,
	daemonCfg *option.DaemonConfig,
) (resource.Resource[*v2alpha1.CiliumNetworkDriverClusterConfig], error) {
	if !cs.IsEnabled() || !daemonCfg.EnableCiliumNetworkDriver {
		return nil, nil
	}

	lw := utils.ListerWatcherWithModifiers(
		utils.ListerWatcherFromTyped(cs.CiliumV2alpha1().CiliumNetworkDriverClusterConfigs()),
	)

	return resource.New[*v2alpha1.CiliumNetworkDriverClusterConfig](
		lc,
		lw,
		mp,
		resource.WithMetric("CiliumNetworkDriverClusterConfig"),
	), nil
}

// ciliumNetworkDriverNodeConfig creates a Resource for watching
// CiliumNetworkDriverNodeConfig custom resources. Returns nil if the
// Kubernetes clientset is not enabled, allowing graceful degradation.
func ciliumNetworkDriverNodeConfig(
	lc cell.Lifecycle,
	cs client.Clientset,
	mp workqueue.MetricsProvider,
	daemonCfg *option.DaemonConfig,
) (resource.Resource[*v2alpha1.CiliumNetworkDriverNodeConfig], error) {
	if !cs.IsEnabled() || !daemonCfg.EnableCiliumNetworkDriver {
		return nil, nil
	}

	lw := utils.ListerWatcherWithModifiers(
		utils.ListerWatcherFromTyped(cs.CiliumV2alpha1().CiliumNetworkDriverNodeConfigs()),
	)

	return resource.New[*v2alpha1.CiliumNetworkDriverNodeConfig](
		lc,
		lw,
		mp,
		resource.WithMetric("CiliumNetworkDriverNodeConfig"),
	), nil
}
