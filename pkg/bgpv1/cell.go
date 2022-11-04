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

	cell.Provide(agent.NewController),
	// goBGP is currently the only supported RouterManager, if more are
	// implemented, provide the manager via a Cell that pics implementation based on configuration.
	cell.ProvidePrivate(gobgp.NewBGPRouterManager),
)
