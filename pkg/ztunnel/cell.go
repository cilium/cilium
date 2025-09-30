// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ztunnel

import (
	"github.com/cilium/hive/cell"

	"github.com/cilium/cilium/pkg/ztunnel/config"
	"github.com/cilium/cilium/pkg/ztunnel/reconciler"
	"github.com/cilium/cilium/pkg/ztunnel/xds"
	"github.com/cilium/cilium/pkg/ztunnel/zds"
)

// Cell starts an xDS server scoped specifically for zTunnel integration.
var Cell = cell.Module(
	"ztunnel",
	"ztunnel certificate authority and control plane",
	cell.Config(config.DefaultConfig),
	// ZDS server for ztunnel
	zds.Cell,
	// XDS control plane for ztunnel
	xds.Cell,
	// Reconciler for namespace enrollment for ztunnel mTLS
	reconciler.Cell,
)
