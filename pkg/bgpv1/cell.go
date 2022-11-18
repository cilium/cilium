// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package bgpv1

import (
	"github.com/cilium/cilium/pkg/bgpv1/agent"
	"github.com/cilium/cilium/pkg/bgpv1/gobgp"
	"github.com/cilium/cilium/pkg/hive/cell"
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
	// goBGP is currently the only supported RouterManager, if more are
	// implemented, provide the manager via a Cell that pics implementation based on configuration.
	cell.ProvidePrivate(gobgp.NewBGPRouterManager),
)
