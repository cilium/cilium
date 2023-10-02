package mtu

import (
	"github.com/cilium/cilium/daemon/cmd/cni"
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

func newForCell(lc hive.Lifecycle, localNode *node.LocalNodeStore, ipsec types.IPSec, cni cni.CNIConfigManager) MTU {
	c := &Configuration{}
	lc.Append(hive.Hook{
		OnStart: func(ctx hive.HookContext) error {
			node, err := localNode.Get(ctx)
			if err != nil {
				return err
			}
			externalIP := node.GetNodeIP(false)
			if externalIP == nil {
				externalIP = node.GetNodeIP(true)
			}
			configuredMTU := option.Config.MTU
			if mtu := cni.GetMTU(); mtu > 0 {
				configuredMTU = mtu
				log.WithField("mtu", configuredMTU).Info("Overwriting MTU based on CNI configuration")
			}
			*c = NewConfiguration(ipsec.AuthKeySize(), option.Config.EnableIPSec, option.Config.TunnelExists(), option.Config.EnableWireguard,
				option.Config.EnableHighScaleIPcache && option.Config.EnableNodePort, configuredMTU, externalIP)
			return nil
		},
	})
	return c
}
