// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package networkdriver

import (
	"github.com/cilium/hive/cell"

	"github.com/cilium/cilium/operator/pkg/networkdriver/config"
	"github.com/cilium/cilium/operator/pkg/networkdriver/ipam"
	networkdriverConfig "github.com/cilium/cilium/pkg/networkdriver/config"
)

var Cell = cell.Group(
	cell.Config(networkdriverConfig.DefaultConfig),

	config.Cell,
	ipam.Cell,
)
