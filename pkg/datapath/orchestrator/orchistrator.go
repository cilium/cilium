// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package orchestrator

import (
	"context"
	"net"

	"github.com/sirupsen/logrus"

	"github.com/cilium/cilium/pkg/datapath/linux/sysctl"
	"github.com/cilium/cilium/pkg/datapath/loader/types"
	"github.com/cilium/cilium/pkg/datapath/tunnel"
	datapath "github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/mtu"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/option"
)

type orchestrator struct {
	params orchestratorParams
}

type orchestratorParams struct {
	cell.In

	Logger  logrus.FieldLogger
	Loader  types.Loader
	Netlink netlink
	Sysctl  sysctl.Sysctl
	Mtu     mtu.MTU
}

func newOrchestrator(params orchestratorParams) *orchestrator {
	return &orchestrator{
		params: params,
	}
}

func (o *orchestrator) Reinitialize(ctx context.Context, owner datapath.BaseProgramOwner, tunnelConfig tunnel.Config, deviceMTU int, iptMgr datapath.IptablesManager, p datapath.Proxy) error {
	hostDev1, _, err := o.setupBaseDevice()
	if err != nil {
		return err
	}

	var nodeIPv4, nodeIPv6 net.IP
	if option.Config.EnableIPv4 {
		nodeIPv4 = node.GetInternalIPv4Router()
	}
	if option.Config.EnableIPv6 {
		nodeIPv6 = node.GetIPv6Router()
		// Docker <17.05 has an issue which causes IPv6 to be disabled in the initns for all
		// interface (https://github.com/docker/libnetwork/issues/1720)
		// Enable IPv6 for now
		if err := o.params.Sysctl.Disable("net.ipv6.conf.all.disable_ipv6"); err != nil {
			return err
		}
	}

	if err := o.addHostDeviceAddr(hostDev1, nodeIPv4, nodeIPv6); err != nil {
		return err
	}

	return o.params.Loader.Reinitialize(ctx, owner, tunnelConfig, deviceMTU, iptMgr, p)
}
