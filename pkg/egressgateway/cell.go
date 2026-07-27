// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package egressgateway

import (
	"github.com/cilium/hive/cell"

	"github.com/cilium/cilium/pkg/datapath/tunnel"
	"github.com/cilium/cilium/pkg/option"
)

// Cell provides a [Manager] for consumption with hive.
var Cell = cell.Module(
	"egressgateway",
	"Egress Gateway allows originating traffic from specific addresses",
	cell.Config(defaultConfig),
	cell.Provide(NewEgressGatewayManager),
	cell.Provide(newPolicyResource),
	cell.Provide(func(dcfg *option.DaemonConfig) tunnel.EnablerOut {
		if !dcfg.EnableEgressGateway {
			return tunnel.EnablerOut{}
		}
		return tunnel.NewEnabler(true)
	}),
)
