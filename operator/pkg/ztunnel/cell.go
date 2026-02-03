// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ztunnel

import (
	"github.com/cilium/hive/cell"

	"github.com/cilium/cilium/operator/pkg/ztunnel/config"
)

// Cell provides ztunnel configuration.
var Cell = cell.Module(
	"ztunnel",
	"ZTunnel Configuration",

	cell.Config(config.DefaultConfig),
)
