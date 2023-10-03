// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package config

import (
	"github.com/cilium/cilium/pkg/datapath/linux/bandwidth"
	dpdef "github.com/cilium/cilium/pkg/datapath/linux/config/defines"
	"github.com/cilium/cilium/pkg/datapath/tables"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/statedb"
)

type configWriterParams struct {
	cell.In

	NodeExtraDefines   []dpdef.Map `group:"header-node-defines"`
	NodeExtraDefineFns []dpdef.Fn  `group:"header-node-define-fns"`
	BandwidthManager   *bandwidth.Manager
	DB                 *statedb.DB
	Devices            statedb.Table[*tables.Device]
}

var Cell = cell.Module(
	"datapath-config-writer",
	"Generate and write the configuration for datapath program types",

	cell.Provide(NewHeaderfileWriter),
)
