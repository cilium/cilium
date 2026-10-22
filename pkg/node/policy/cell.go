// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package policy

import (
	"log/slog"

	"github.com/cilium/hive/cell"
	"github.com/cilium/statedb"

	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/datapath/tunnel"
	"github.com/cilium/cilium/pkg/ipcache"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/option"
	wgTypes "github.com/cilium/cilium/pkg/wireguard/types"
)

// Cell installs the node update policy.
var Cell = cell.Module(
	"node-policy",
	"Applies node update policy",
	cell.Invoke(installUpdatePolicy),
)

func installUpdatePolicy(in struct {
	cell.In
	Logger      *slog.Logger
	ClusterInfo cmtypes.ClusterInfo
	TunnelConf  tunnel.Config
	IPCache     *ipcache.IPCache
	DB          *statedb.DB
	WGConfig    wgTypes.Config
	Writer      *node.Writer
},
) error {
	_, err := newUpdatePolicy(
		in.Logger,
		option.Config,
		in.ClusterInfo,
		in.TunnelConf,
		in.IPCache,
		in.DB,
		in.WGConfig,
		in.Writer,
	)
	return err
}
