// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package orchestrator

import (
	"context"
	"errors"
	"fmt"

	"github.com/cilium/statedb"

	"github.com/cilium/cilium/pkg/cidr"
	"github.com/cilium/cilium/pkg/common"
	"github.com/cilium/cilium/pkg/datapath/tables"
	datapath "github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/datapath/xdp"
	"github.com/cilium/cilium/pkg/defaults"
	ipamOption "github.com/cilium/cilium/pkg/ipam/option"
	"github.com/cilium/cilium/pkg/kpr"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/mac"
	"github.com/cilium/cilium/pkg/maglev"
	"github.com/cilium/cilium/pkg/mtu"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/svcrouteconfig"
	wgTypes "github.com/cilium/cilium/pkg/wireguard/types"
)

const (
	// AutoCIDR indicates that a CIDR should be allocated
	AutoCIDR = "auto"
)

// newLocalNodeConfig constructs LocalNodeConfiguration from the global agent
// data sources.

// LocalNodeConfiguration encapsulates the datapath relevant part of dynamic
// state of the agent, which allows the datapath code to operate against a
// pure data struct rather than complex APIs. When this data changes a new
// LocalNodeConfiguration instance is generated. Previous LocalNodeConfiguration
// is never mutated in-place.
func newLocalNodeConfig(
	ctx context.Context,
	config *option.DaemonConfig,
	localNode node.LocalNode,
	txn statedb.ReadTxn,
	directRoutingDevTbl tables.DirectRoutingDevice,
	devices statedb.Table[*tables.Device],
	nodeAddresses statedb.Table[tables.NodeAddress],
	masqInterface string,
	xdpConfig xdp.Config,
	lbConfig loadbalancer.Config,
	kprCfg kpr.KPRConfig,
	svcCfg svcrouteconfig.RoutesConfig,
	maglevConfig maglev.Config,
	mtuTbl statedb.Table[mtu.RouteMTU],
	wgAgent wgTypes.WireguardAgent,
	ipsecCfg datapath.IPsecConfig,
) (datapath.LocalNodeConfiguration, <-chan struct{}, error) {
	auxPrefixes := []*cidr.CIDR{}

	if config.IPv4ServiceRange != AutoCIDR {
		serviceCIDR, err := cidr.ParseCIDR(config.IPv4ServiceRange)
		if err != nil {
			return datapath.LocalNodeConfiguration{}, nil, fmt.Errorf("Invalid IPv4 service prefix %q: %w", config.IPv4ServiceRange, err)
		}

		auxPrefixes = append(auxPrefixes, serviceCIDR)
	}

	if config.IPv6ServiceRange != AutoCIDR {
		serviceCIDR, err := cidr.ParseCIDR(config.IPv6ServiceRange)
		if err != nil {
			return datapath.LocalNodeConfiguration{}, nil, fmt.Errorf("Invalid IPv6 service prefix %q: %w", config.IPv6ServiceRange, err)
		}

		auxPrefixes = append(auxPrefixes, serviceCIDR)
	}

	nativeDevices, devsWatch := tables.SelectedDevices(devices, txn)
	nodeAddrsIter, addrsWatch := nodeAddresses.AllWatch(txn)
	mtuRoute, _, mtuWatch, _ := mtuTbl.GetWatch(txn, mtu.MTURouteIndex.Query(mtu.DefaultPrefixV4))

	watchChans := []<-chan struct{}{devsWatch, addrsWatch, mtuWatch}
	var directRoutingDevice *tables.Device
	if option.Config.DirectRoutingDeviceRequired(kprCfg, wgAgent.Enabled()) {
		drd, directRoutingDevWatch := directRoutingDevTbl.Get(ctx, txn)
		if drd == nil {
			return datapath.LocalNodeConfiguration{}, nil, errors.New("direct routing device required but not configured")
		}

		watchChans = append(watchChans, directRoutingDevWatch)
		directRoutingDevice = drd
	}

	var wgIndex uint32
	if wgAgent.Enabled() {
		var err error
		wgIndex, err = wgAgent.IfaceIndex()
		if err != nil {
			return datapath.LocalNodeConfiguration{}, nil, fmt.Errorf("getting Wireguard device index: %w", err)
		}
	}

	nameDevice := devicesMap(txn, devices)
	ciliumHostDevice, ok := nameDevice[defaults.HostDevice]
	if !ok {
		return datapath.LocalNodeConfiguration{}, nil, fmt.Errorf("failed to look up link '%s'", defaults.HostDevice)
	}
	ciliumHostMAC, err := mac.ParseMAC(ciliumHostDevice.HardwareAddr.String())
	if err != nil {
		return datapath.LocalNodeConfiguration{}, nil, fmt.Errorf("failed to parse hardware address of '%s': %w", defaults.HostDevice, err)
	}

	ciliumNetDevice, ok := nameDevice[defaults.SecondHostDevice]
	if !ok {
		return datapath.LocalNodeConfiguration{}, nil, fmt.Errorf("failed to look up link '%s'", defaults.SecondHostDevice)
	}
	ciliumNetMAC, err := mac.ParseMAC(ciliumNetDevice.HardwareAddr.String())
	if err != nil {
		return datapath.LocalNodeConfiguration{}, nil, fmt.Errorf("failed to parse hardware address of '%s': %w", defaults.SecondHostDevice, err)
	}

	return datapath.LocalNodeConfiguration{
		NodeIPv4:                     localNode.GetNodeIP(false),
		NodeIPv6:                     localNode.GetNodeIP(true),
		CiliumInternalIPv4:           localNode.GetCiliumInternalIP(false),
		CiliumInternalIPv6:           localNode.GetCiliumInternalIP(true),
		CiliumNetIfIndex:             uint32(ciliumNetDevice.Index),
		CiliumNetMAC:                 ciliumNetMAC,
		CiliumHostIfIndex:            uint32(ciliumHostDevice.Index),
		CiliumHostMAC:                ciliumHostMAC,
		AllocCIDRIPv4:                localNode.IPv4AllocCIDR,
		AllocCIDRIPv6:                localNode.IPv6AllocCIDR,
		NativeRoutingCIDRIPv4:        datapath.RemoteSNATDstAddrExclusionCIDRv4(localNode),
		NativeRoutingCIDRIPv6:        datapath.RemoteSNATDstAddrExclusionCIDRv6(localNode),
		ServiceLoopbackIPv4:          localNode.Local.ServiceLoopbackIPv4,
		ServiceLoopbackIPv6:          localNode.Local.ServiceLoopbackIPv6,
		Devices:                      nativeDevices,
		NodeAddresses:                statedb.Collect(nodeAddrsIter),
		DirectRoutingDevice:          directRoutingDevice,
		DeriveMasqIPAddrFromDevice:   masqInterface,
		HostEndpointID:               node.GetEndpointID(),
		DeviceMTU:                    mtuRoute.DeviceMTU,
		RouteMTU:                     mtuRoute.RouteMTU,
		RoutePostEncryptMTU:          mtuRoute.RoutePostEncryptMTU,
		AuxiliaryPrefixes:            auxPrefixes,
		EnableIPv4:                   config.EnableIPv4,
		EnableIPv6:                   config.EnableIPv6,
		EnableEncapsulation:          config.TunnelingEnabled(),
		EnableAutoDirectRouting:      config.EnableAutoDirectRouting,
		DirectRoutingSkipUnreachable: config.DirectRoutingSkipUnreachable,
		EnableLocalNodeRoute:         config.EnableLocalNodeRoute && config.IPAM != ipamOption.IPAMENI && config.IPAM != ipamOption.IPAMAzure && config.IPAM != ipamOption.IPAMAlibabaCloud,
		EnableWireguard:              wgAgent.Enabled(),
		WireguardIfIndex:             wgIndex,
		EnableIPSec:                  ipsecCfg.Enabled(),
		EncryptNode:                  config.EncryptNode,
		IPv4PodSubnets:               cidr.NewCIDRSlice(config.IPv4PodSubnets),
		IPv6PodSubnets:               cidr.NewCIDRSlice(config.IPv6PodSubnets),
		XDPConfig:                    xdpConfig,
		LBConfig:                     lbConfig,
		KPRConfig:                    kprCfg,
		SvcRouteConfig:               svcCfg,
		MaglevConfig:                 maglevConfig,
	}, common.MergeChannels(watchChans...), nil
}

func devicesMap(txn statedb.ReadTxn, devices statedb.Table[*tables.Device]) map[string]*tables.Device {
	nameDevice := make(map[string]*tables.Device)
	for d := range devices.All(txn) {
		nameDevice[d.Name] = d
	}
	return nameDevice
}
