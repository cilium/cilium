// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package mtu

import (
	"github.com/cilium/cilium/daemon/cmd/cni"
	"github.com/cilium/cilium/pkg/datapath/tunnel"
	"github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/option"
)

var Cell = cell.Module(
	"mtu",
	"MTU discovery",

	cell.Provide(newForCell),
)

type MTU interface {
	GetDeviceMTU() int
	GetRouteMTU() int
	GetRoutePostEncryptMTU() int
}

type mtuParams struct {
	cell.In

	LocalNode    *node.LocalNodeStore
	IPsec        types.IPsecKeyCustodian
	CNI          cni.CNIConfigManager
	TunnelConfig tunnel.Config
}

func newForCell(lc hive.Lifecycle, p mtuParams) MTU {
	c := &Configuration{}
	lc.Append(hive.Hook{
		OnStart: func(ctx hive.HookContext) error {
			node, err := p.LocalNode.Get(ctx)
			if err != nil {
				return err
			}
			externalIP := node.GetNodeIP(false)
			if externalIP == nil {
				externalIP = node.GetNodeIP(true)
			}
			configuredMTU := option.Config.MTU
			if mtu := p.CNI.GetMTU(); mtu > 0 {
				configuredMTU = mtu
				log.WithField("mtu", configuredMTU).Info("Overwriting MTU based on CNI configuration")
			}
			*c = NewConfiguration(
				p.IPsec.AuthKeySize(),
				option.Config.EnableIPSec,
				p.TunnelConfig.ShouldAdaptMTU(),
				option.Config.EnableWireguard,
				option.Config.EnableHighScaleIPcache && option.Config.EnableNodePort,
				configuredMTU,
				externalIP,
			)
			return nil
		},
	})
	return c
}
