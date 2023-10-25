// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package datapath

import (
	"context"
	"fmt"
	"net"
	"strings"

	"github.com/spf13/pflag"

	"github.com/cilium/cilium/pkg/cidr"
	"github.com/cilium/cilium/pkg/datapath/tables"
	"github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/ip"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/statedb"
)

var NodeAddressingCell = cell.Module(
	"node-addressing",
	"Accessors for looking up local node IP addresses",

	cell.Config(nodeAddressingConfig{}),
	cell.ProvidePrivate(newAddressScopeMax),
	cell.Provide(NewNodeAddressing),
)

const (
	addressScopeMaxFlag = "local-max-addr-scope"
)

type nodeAddressingConfig struct {
	// AddressScopeMax controls the maximum address scope for addresses to be
	// considered local ones. Affects which addresses are used for NodePort
	// and which have HOST_ID in the ipcache.
	AddressScopeMax string `mapstructure:"local-max-addr-scope"`
}

func (nodeAddressingConfig) Flags(flags *pflag.FlagSet) {
	flags.String(addressScopeMaxFlag, fmt.Sprintf("%d", defaults.AddressScopeMax), "Maximum local address scope for ipcache to consider host addresses")
	flags.MarkHidden(addressScopeMaxFlag)
}

type AddressScopeMax uint8

func newAddressScopeMax(cfg nodeAddressingConfig) (AddressScopeMax, error) {
	scope, err := ip.ParseScope(cfg.AddressScopeMax)
	if err != nil {
		return 0, fmt.Errorf("Cannot parse scope integer from --%s option", addressScopeMaxFlag)
	}
	return AddressScopeMax(scope), nil
}

func NewNodeAddressing(addressScopeMax AddressScopeMax, localNode *node.LocalNodeStore, db *statedb.DB, nodeAddresses statedb.Table[tables.NodeAddress], devices statedb.Table[*tables.Device]) types.NodeAddressing {
	return &nodeAddressing{
		addressScopeMax: addressScopeMax,
		localNode:       localNode,
		db:              db,
		nodeAddresses:   nodeAddresses,
		devices:         devices,
	}
}

func (a addressFamilyIPv4) Router() net.IP {
	if n, err := a.localNode.Get(context.Background()); err == nil {
		return n.GetCiliumInternalIP(false)
	}
	return nil
}

func (a addressFamilyIPv4) PrimaryExternal() net.IP {
	if n, err := a.localNode.Get(context.Background()); err == nil {
		return n.GetNodeIP(false)
	}
	return nil
}

func (a addressFamilyIPv4) AllocationCIDR() *cidr.CIDR {
	if n, err := a.localNode.Get(context.Background()); err == nil {
		return n.IPv4AllocCIDR
	}
	return nil
}

func (a addressFamilyIPv4) LocalAddresses() (addrs []net.IP, err error) {
	return a.getLocalAddresses(a.db.ReadTxn(), false)
}

// LoadBalancerNodeAddresses returns all IPv4 node addresses on which the
// loadbalancer should implement HostPort and NodePort services.
func (a addressFamilyIPv4) LoadBalancerNodeAddresses() []net.IP {
	addrs := a.getNodeAddresses(a.db.ReadTxn(), false)
	addrs = append(addrs, net.IPv4zero)
	return addrs
}

func (a addressFamilyIPv4) DirectRouting() (int, net.IP, bool) {
	return a.directRouting(false)
}

func (a addressFamilyIPv6) Router() net.IP {
	if n, err := a.localNode.Get(context.Background()); err == nil {
		return n.GetCiliumInternalIP(true)
	}
	return nil
}

func (a addressFamilyIPv6) PrimaryExternal() net.IP {
	if n, err := a.localNode.Get(context.Background()); err == nil {
		return n.GetNodeIP(true)
	}
	return nil
}

func (a addressFamilyIPv6) AllocationCIDR() *cidr.CIDR {
	if n, err := a.localNode.Get(context.Background()); err == nil {
		return n.IPv6AllocCIDR
	}
	return nil
}

func (a addressFamilyIPv6) LocalAddresses() ([]net.IP, error) {
	return a.getLocalAddresses(a.db.ReadTxn(), true)
}

// LoadBalancerNodeAddresses returns all IPv6 node addresses on which the
// loadbalancer should implement HostPort and NodePort services.
func (a addressFamilyIPv6) LoadBalancerNodeAddresses() []net.IP {
	addrs := a.getNodeAddresses(a.db.ReadTxn(), true)
	addrs = append(addrs, net.IPv6zero)
	return addrs
}

func (a addressFamilyIPv6) DirectRouting() (int, net.IP, bool) {
	return a.directRouting(true)
}

type nodeAddressing struct {
	addressScopeMax AddressScopeMax
	localNode       *node.LocalNodeStore
	db              *statedb.DB
	nodeAddresses   statedb.Table[tables.NodeAddress]
	devices         statedb.Table[*tables.Device]
}

func (na *nodeAddressing) getNodeAddresses(txn statedb.ReadTxn, ipv6 bool) (addrs []net.IP) {
	nodeAddrs, _ := na.nodeAddresses.All(txn)
	for addr, _, ok := nodeAddrs.Next(); ok; addr, _, ok = nodeAddrs.Next() {
		if ipv6 && addr.Addr.Is4() {
			continue
		}
		if !ipv6 && !addr.Addr.Is4() {
			continue
		}
		addrs = append(addrs, addr.IP())
	}
	return
}

func (na *nodeAddressing) getLocalAddresses(txn statedb.ReadTxn, ipv6 bool) (addrs []net.IP, err error) {
	// TODO: LocalAddresses() is really used only to update ipcache with "HOST_ID" IPs and
	// by ctmap gc. Could move this code to a controller that updates ipcache and ctmap gc
	// could get host_id ips from ipcache. Would also be good to lock down what exactly is
	// a "local address" and how it differs from "node address".
	//
	// This code currently tries to stay as compatible with the original code as possible
	// and thus goes through all devices.

	devices, _ := na.devices.All(txn)
	for dev, _, ok := devices.Next(); ok; dev, _, ok = devices.Next() {
		if dev.Flags&net.FlagUp == 0 {
			continue
		}
		if strings.HasPrefix(dev.Name, "lxc") || strings.HasPrefix(dev.Name, "docker") {
			// TODO: use defaults.ExcludedDevicePrefixes but keep cilium_host?
			continue
		}
		for _, addr := range dev.Addrs {
			// Keep the scope-based address filtering as was introduced
			// in 080857bdedca67d58ec39f8f96c5f38b22f6dc0b.

			if addr.Scope > uint8(na.addressScopeMax) {
				continue
			}
			if addr.Addr.IsLoopback() {
				continue
			}
			if ipv6 && addr.Addr.Is4() {
				continue
			}
			if !ipv6 && !addr.Addr.Is4() {
				continue
			}
			addrs = append(addrs, addr.AsIP())
		}
	}
	return addrs, nil
}

func (na *nodeAddressing) directRouting(ipv6 bool) (int, net.IP, bool) {
	deviceName := option.Config.DirectRoutingDevice
	if deviceName == "" {
		return 0, nil, false
	}
	dev, _, ok := na.devices.First(na.db.ReadTxn(), tables.DeviceNameIndex.Query(option.Config.DirectRoutingDevice))
	if !ok {
		return 0, nil, false
	}
	var addr net.IP
	for _, a := range dev.Addrs {
		if ipv6 && a.Addr.Is6() {
			addr = a.AsIP()
			break
		} else if !ipv6 && a.Addr.Is4() {
			addr = a.AsIP()
			break
		}
	}
	return dev.Index, addr, true
}

type addressFamilyIPv4 struct{ *nodeAddressing }
type addressFamilyIPv6 struct{ *nodeAddressing }

func (n *nodeAddressing) IPv6() types.NodeAddressingFamily {
	return addressFamilyIPv6{n}
}

func (n *nodeAddressing) IPv4() types.NodeAddressingFamily {
	return addressFamilyIPv4{n}
}
