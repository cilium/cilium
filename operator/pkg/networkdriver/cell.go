// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package networkdriver

import (
	"github.com/cilium/hive/cell"

	"github.com/cilium/cilium/operator/pkg/networkdriver/config"
	"github.com/cilium/cilium/operator/pkg/networkdriver/ipam"
)

var Cell = cell.Module(
	"cilium-network-driver",
	"Cilium Network Driver IPAM and node configuration management",

	ipam.Cell,
	config.Cell,
)
