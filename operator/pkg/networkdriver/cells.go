// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package networkdriver

import (
	"github.com/cilium/hive/cell"

	"github.com/cilium/cilium/operator/pkg/networkdriver/config"
	"github.com/cilium/cilium/operator/pkg/networkdriver/ipam"
)

// Cell provides operator-side Network Driver functionality, including:
// - Config controller: reconciles ClusterConfig to NodeConfig resources
// - IPAM: multi-pool IP address management for network devices
var Cell = cell.Module(
	"networkdriver",
	"Cilium Network Driver",

	config.Cell,
	ipam.Cell,
)
