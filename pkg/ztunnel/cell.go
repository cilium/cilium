// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ztunnel

import (
	"github.com/cilium/hive/cell"

	"github.com/cilium/cilium/pkg/ztunnel/config"
	"github.com/cilium/cilium/pkg/ztunnel/xds"
)

// Cell starts ztunnel related control-plane components.
var Cell = cell.Module(
	"ztunnel",
	"ztunnel related control-plane components",
	cell.Config(config.DefaultConfig),

	// XDS control plane for ztunnel
	xds.Cell,
)
