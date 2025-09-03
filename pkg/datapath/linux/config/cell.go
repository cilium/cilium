// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package config

import (
	"log/slog"

	"github.com/cilium/hive/cell"

	dpdef "github.com/cilium/cilium/pkg/datapath/linux/config/defines"
	"github.com/cilium/cilium/pkg/datapath/linux/sysctl"
	datapath "github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/kpr"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/maps/nodemap"
)

type WriterParams struct {
	cell.In

	Log                *slog.Logger
	LBConfig           loadbalancer.Config
	NodeMap            nodemap.MapV2
	NodeAddressing     datapath.NodeAddressing
	NodeExtraDefines   []dpdef.Map `group:"header-node-defines"`
	NodeExtraDefineFns []dpdef.Fn  `group:"header-node-define-fns"`
	Sysctl             sysctl.Sysctl
	KPRConfig          kpr.KPRConfig
	IPSecConfig        datapath.IPsecConfig
}

var Cell = cell.Module(
	"datapath-linux-config",
	"Generate and write the configuration for datapath program types",

	cell.Provide(NewHeaderfileWriter),
)
