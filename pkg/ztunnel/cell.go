// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ztunnel

import (
	"github.com/cilium/hive/cell"

	"github.com/cilium/cilium/pkg/ztunnel/config"
	"github.com/cilium/cilium/pkg/ztunnel/reconciler"
	"github.com/cilium/cilium/pkg/ztunnel/zds"
)

// Cell starts ztunnel related control-plane components.
var Cell = cell.Module(
	"ztunnel",
	"ztunnel related control-plane components",
	cell.Config(config.DefaultConfig),

	// Reconciler for namespace enrollment for ztunnel mTLS
	reconciler.Cell,

	// ZDS server for ztunnel
	zds.Cell,
)
