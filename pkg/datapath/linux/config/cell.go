// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package config

import (
	"github.com/sirupsen/logrus"

	"github.com/cilium/cilium/pkg/datapath/linux/bandwidth"
	dpdef "github.com/cilium/cilium/pkg/datapath/linux/config/defines"
	datapath "github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/hive/cell"
)

type WriterParams struct {
	cell.In

	Log                logrus.FieldLogger
	NodeAddressing     datapath.NodeAddressing
	NodeExtraDefines   []dpdef.Map `group:"header-node-defines"`
	NodeExtraDefineFns []dpdef.Fn  `group:"header-node-define-fns"`
	BandwidthManager   bandwidth.Manager
}

var Cell = cell.Module(
	"datapath-linux-config",
	"Generate and write the configuration for datapath program types",

	cell.Provide(NewHeaderfileWriter),
)
