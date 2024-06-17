// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package mtu

import (
	"github.com/cilium/hive/cell"
	"github.com/spf13/pflag"

	"github.com/cilium/cilium/daemon/cmd/cni"
	"github.com/cilium/cilium/pkg/datapath/tunnel"
	"github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/option"
)

var Cell = cell.Module(
	"mtu",
	"MTU discovery",

	cell.Provide(newForCell),
	cell.Config(defaultConfig),
)

type MTU interface {
	GetDeviceMTU() int
	GetRouteMTU() int
	GetRoutePostEncryptMTU() int
	IsEnableRouteMTUForCNIChaining() bool
}

type mtuParams struct {
	cell.In

	LocalNode    *node.LocalNodeStore
	IPsec        types.IPsecKeyCustodian
	CNI          cni.CNIConfigManager
	TunnelConfig tunnel.Config

	Config Config
}

type Config struct {
	// Enable route MTU for pod netns when CNI chaining is used
	EnableRouteMTUForCNIChaining bool
}

var defaultConfig = Config{
	EnableRouteMTUForCNIChaining: false,
}

func (c Config) Flags(flags *pflag.FlagSet) {
	flags.Bool("enable-route-mtu-for-cni-chaining", c.EnableRouteMTUForCNIChaining, "Enable route MTU for pod netns when CNI chaining is used")
}

func newForCell(lc cell.Lifecycle, p mtuParams, cc Config) MTU {
	c := &Configuration{}
	lc.Append(cell.Hook{
		OnStart: func(ctx cell.HookContext) error {
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
				cc.EnableRouteMTUForCNIChaining,
			)
			return nil
		},
	})
	return c
}
