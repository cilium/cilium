// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package egressmap

import "github.com/cilium/hive/cell"

// ConfigurePolicyMapsCell is exported to make policy maps configurable from tests.
var ConfigurePolicyMapsCell = cell.Invoke(configurePolicyMaps)

var Cell = cell.Module(
	"egressmaps",
	"Egressmaps provide access to the egress gateway datapath maps",
	cell.Config(DefaultPolicyConfig),
	cell.Provide(createPolicyMaps),
	ConfigurePolicyMapsCell,
)
