// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package bgpv1

import (
	"github.com/cilium/cilium/pkg/bgpv1/agent"
	"github.com/cilium/cilium/pkg/bgpv1/gobgp"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
	v2alpha1api "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/client/clientset/versioned/typed/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/k8s/utils"
)

var Cell = cell.Module(
	"bgp-cp",
	"BGP Control Plane",

	// The Controller which is the entry point of the module
	cell.Provide(agent.NewController),
	// Signaler is used by all cells that observe resources to signal the controller to start reconciliation.
	cell.ProvidePrivate(agent.NewSignaler),
	// Local Node Store Specer provides the module with information about the current node.
	cell.ProvidePrivate(agent.NewLocalNodeStoreSpecer),
	// BGP Peering Policy resource provides the module with a stream of events for the BGPPeeringPolicy resource.
	cell.ProvidePrivate(newBGPPeeringPolicyResource),
	// goBGP is currently the only supported RouterManager, if more are
	// implemented, provide the manager via a Cell that pics implementation based on configuration.
	cell.ProvidePrivate(gobgp.NewBGPRouterManager),
)

func newBGPPeeringPolicyResource(lc hive.Lifecycle, c client.Clientset) resource.Resource[*v2alpha1api.CiliumBGPPeeringPolicy] {
	var listerWatcher v2alpha1.CiliumBGPPeeringPolicyInterface
	if c.IsEnabled() {
		listerWatcher = c.CiliumV2alpha1().CiliumBGPPeeringPolicies()
	}

	return resource.New[*v2alpha1api.CiliumBGPPeeringPolicy](
		lc, utils.ListerWatcherFromTyped[*v2alpha1api.CiliumBGPPeeringPolicyList](
			listerWatcher,
		))
}
