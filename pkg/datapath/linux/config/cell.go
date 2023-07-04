// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package config

import (
	dpdef "github.com/cilium/cilium/pkg/datapath/linux/config/defines"
	dptypes "github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/hive/cell"
)

var Cell = cell.Module(
	"datapath-config-writer",
	"Generate and write the configuration for datapath program types",

	cell.Provide(
		func(in struct {
			cell.In
			NodeExtraDefines []dpdef.Fn `group:"header-node-defines"`
		}) dptypes.ConfigWriter {
			return &HeaderfileWriter{nodeExtraDefines: in.NodeExtraDefines}
		},
	),
)
