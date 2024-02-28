// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package orchestrator

import (
	"context"
	"fmt"
	"net"

	"github.com/sirupsen/logrus"

	"github.com/cilium/cilium/pkg/datapath/linux/linux_defaults"
	"github.com/cilium/cilium/pkg/datapath/linux/route"
	"github.com/cilium/cilium/pkg/datapath/linux/sysctl"
	"github.com/cilium/cilium/pkg/datapath/loader/types"
	"github.com/cilium/cilium/pkg/datapath/tables"
	"github.com/cilium/cilium/pkg/datapath/tunnel"
	datapath "github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/hive/cell"
	ipamOption "github.com/cilium/cilium/pkg/ipam/option"
	"github.com/cilium/cilium/pkg/mtu"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/statedb"
)

type orchestrator struct {
	params orchestratorParams
}

type orchestratorParams struct {
	cell.In

	Logger    logrus.FieldLogger
	Loader    types.Loader
	Netlink   netlink
	Sysctl    sysctl.Sysctl
	Mtu       mtu.MTU
	DB        *statedb.DB
	RouteTbl  statedb.Table[*tables.Route]
	DeviceTbl statedb.Table[*tables.Device]
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

	if option.Config.EnableHealthDatapath {
		_ = o.params.Sysctl.WriteInt("net.core.fb_tunnels_only_for_init_net", 2)

		if err := o.setupIPIPDevices(option.Config.IPv4Enabled(), option.Config.IPv6Enabled()); err != nil {
			return fmt.Errorf("unable to create ipip encapsulation devices for health datapath")
		}
	}

	if err := o.setupTunnelDevice(tunnelConfig); err != nil {
		return err
	}

	if option.Config.IPAM == ipamOption.IPAMENI {
		if err := o.addENIRules(); err != nil {
			return fmt.Errorf("unable to install ip rule for ENI multi-node NodePort: %w", err)
		}
	}

	return o.params.Loader.Reinitialize(ctx, owner, tunnelConfig, deviceMTU, iptMgr, p)
}

func (o *orchestrator) addENIRules() error {
	// AWS ENI mode requires symmetric routing, see
	// iptables.addCiliumENIRules().
	// The default AWS daemonset installs the following rules that are used
	// for NodePort traffic between nodes:
	//
	// # iptables -t mangle -A PREROUTING -i eth0 -m comment --comment "AWS, primary ENI" -m addrtype --dst-type LOCAL --limit-iface-in -j CONNMARK --set-xmark 0x80/0x80
	// # iptables -t mangle -A PREROUTING -i eni+ -m comment --comment "AWS, primary ENI" -j CONNMARK --restore-mark --nfmask 0x80 --ctmask 0x80
	// # ip rule add fwmark 0x80/0x80 lookup main
	//
	// It marks packets coming from another node through eth0, and restores
	// the mark on the return path to force a lookup into the main routing
	// table. Without these rules, the "ip rules" set by the cilium-cni
	// plugin tell the host to lookup into the table related to the VPC for
	// which the CIDR used by the endpoint has been configured.
	//
	// We want to reproduce equivalent rules to ensure correct routing.
	if !option.Config.EnableIPv4 {
		return nil
	}

	rtx := o.params.DB.ReadTxn()
	routes := tables.GetDefaultRoutes(o.params.RouteTbl, rtx)

	// Only select the IPv4 default route, since we will be setting a IPv4 specific sysctl.
	var defRoute *tables.Route
	for _, r := range routes {
		if r.Dst.Addr().Is4() {
			defRoute = r
			break
		}
	}

	if defRoute == nil {
		return fmt.Errorf("failed to find interface with IPv4 default route")
	}

	dev, _, found := o.params.DeviceTbl.First(rtx, tables.DeviceIDIndex.Query(defRoute.LinkIndex))
	if !found {
		return fmt.Errorf("failed to find device with index %d", defRoute.LinkIndex)
	}

	_ = o.params.Sysctl.WriteInt(fmt.Sprintf("net.ipv4.conf.%s.rp_filter", dev.Name), 2)

	if err := route.ReplaceRule(route.Rule{
		Priority: linux_defaults.RulePriorityNodeport,
		Mark:     linux_defaults.MarkMultinodeNodeport,
		Mask:     linux_defaults.MaskMultinodeNodeport,
		Table:    route.MainTable,
		Protocol: linux_defaults.RTProto,
	}); err != nil {
		return fmt.Errorf("unable to install ip rule for ENI multi-node NodePort: %w", err)
	}

	return nil
}
