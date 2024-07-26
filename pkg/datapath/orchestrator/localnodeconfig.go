// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package orchestrator

import (
	"context"
	"fmt"

	"github.com/cilium/statedb"

	"github.com/cilium/cilium/pkg/cidr"
	"github.com/cilium/cilium/pkg/datapath/tables"
	datapath "github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/datapath/xdp"
	ipamOption "github.com/cilium/cilium/pkg/ipam/option"
	"github.com/cilium/cilium/pkg/mtu"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/option"
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
	mtu mtu.MTU,
	txn statedb.ReadTxn,
	directRoutingDevTbl tables.DirectRoutingDevice,
	devices statedb.Table[*tables.Device],
	nodeAddresses statedb.Table[tables.NodeAddress],
	xdpConfig xdp.Config,
) (datapath.LocalNodeConfiguration, <-chan struct{}, <-chan struct{}, <-chan struct{}, error) {
	auxPrefixes := []*cidr.CIDR{}

	if config.IPv4ServiceRange != AutoCIDR {
		serviceCIDR, err := cidr.ParseCIDR(config.IPv4ServiceRange)
		if err != nil {
			return datapath.LocalNodeConfiguration{}, nil, nil, nil, fmt.Errorf("Invalid IPv4 service prefix %q: %w", config.IPv4ServiceRange, err)
		}

		auxPrefixes = append(auxPrefixes, serviceCIDR)
	}

	if config.IPv6ServiceRange != AutoCIDR {
		serviceCIDR, err := cidr.ParseCIDR(config.IPv6ServiceRange)
		if err != nil {
			return datapath.LocalNodeConfiguration{}, nil, nil, nil, fmt.Errorf("Invalid IPv6 service prefix %q: %w", config.IPv6ServiceRange, err)
		}

		auxPrefixes = append(auxPrefixes, serviceCIDR)
	}

	directRoutingDevice, directRoutingDevWatch := directRoutingDevTbl.Get(ctx, txn)
	nativeDevices, devsWatch := tables.SelectedDevices(devices, txn)
	nodeAddrsIter, addrsWatch := nodeAddresses.AllWatch(txn)

	return datapath.LocalNodeConfiguration{
		NodeIPv4:                     localNode.GetNodeIP(false),
		NodeIPv6:                     localNode.GetNodeIP(true),
		CiliumInternalIPv4:           localNode.GetCiliumInternalIP(false),
		CiliumInternalIPv6:           localNode.GetCiliumInternalIP(true),
		AllocCIDRIPv4:                localNode.IPv4AllocCIDR,
		AllocCIDRIPv6:                localNode.IPv6AllocCIDR,
		LoopbackIPv4:                 node.GetIPv4Loopback(),
		Devices:                      nativeDevices,
		NodeAddresses:                statedb.Collect(nodeAddrsIter),
		DirectRoutingDevice:          directRoutingDevice,
		HostEndpointID:               node.GetEndpointID(),
		DeviceMTU:                    mtu.GetDeviceMTU(),
		RouteMTU:                     mtu.GetRouteMTU(),
		RoutePostEncryptMTU:          mtu.GetRoutePostEncryptMTU(),
		AuxiliaryPrefixes:            auxPrefixes,
		EnableIPv4:                   config.EnableIPv4,
		EnableIPv6:                   config.EnableIPv6,
		EnableEncapsulation:          config.TunnelingEnabled(),
		EnableAutoDirectRouting:      config.EnableAutoDirectRouting,
		DirectRoutingSkipUnreachable: config.DirectRoutingSkipUnreachable,
		EnableLocalNodeRoute:         config.EnableLocalNodeRoute && config.IPAM != ipamOption.IPAMENI && config.IPAM != ipamOption.IPAMAzure && config.IPAM != ipamOption.IPAMAlibabaCloud,
		EnableIPSec:                  config.EnableIPSec,
		EnableIPSecEncryptedOverlay:  config.EnableIPSecEncryptedOverlay,
		EncryptNode:                  config.EncryptNode,
		IPv4PodSubnets:               cidr.NewCIDRSlice(config.IPv4PodSubnets),
		IPv6PodSubnets:               cidr.NewCIDRSlice(config.IPv6PodSubnets),
		XDPConfig:                    xdpConfig,
	}, devsWatch, addrsWatch, directRoutingDevWatch, nil
}
