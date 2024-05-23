// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package bgpv2

import (
	"github.com/cilium/hive/cell"
)

var Cell = cell.Module(
	"bgp-cp-operator",
	"BGP Control Plane Operator",
	cell.Invoke(registerBGPResourceManager),
)
