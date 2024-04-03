// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package config

import (
	"github.com/sirupsen/logrus"

	dpdef "github.com/cilium/cilium/pkg/datapath/linux/config/defines"
	"github.com/cilium/cilium/pkg/datapath/linux/sysctl"
	datapath "github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/maps/nodemap"
)

type WriterParams struct {
	cell.In

	Log                logrus.FieldLogger
	NodeMap            nodemap.MapV2
	NodeAddressing     datapath.NodeAddressing
	NodeExtraDefines   []dpdef.Map `group:"header-node-defines"`
	NodeExtraDefineFns []dpdef.Fn  `group:"header-node-define-fns"`
	BandwidthManager   datapath.BandwidthManager
	Sysctl             sysctl.Sysctl
}

var Cell = cell.Module(
	"datapath-linux-config",
	"Generate and write the configuration for datapath program types",

	cell.Provide(NewHeaderfileWriter),
)
