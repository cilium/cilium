// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package tables

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/spf13/pflag"
	"k8s.io/apimachinery/pkg/util/sets"

	"github.com/cilium/cilium/pkg/cidr"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/hive/job"
	"github.com/cilium/cilium/pkg/ip"
	"github.com/cilium/cilium/pkg/rate"
	"github.com/cilium/cilium/pkg/statedb"
	"github.com/cilium/cilium/pkg/statedb/index"
)

// NodeAddress is a publicly routable IP address on the local Cilium node.
type NodeAddress struct {
	netip.Addr

	// NodePort is true if this address is to be used for NodePort.
	// If --nodeport-addresses is set, then all addresses on native
	// devices that are contained within the specified CIDRs are chosen.
	// If it is not set, then only the primary IPv4 and/or IPv6 address
	// of each native device is used.
	NodePort bool

	// Primary is true if this is the primary IPv4 or IPv6 address of this device.
	// This is mainly used to pick the address for BPF masquerading.
	Primary    bool
	DeviceName string
}

func (n *NodeAddress) IP() net.IP {
	return n.AsSlice()
}

func (n *NodeAddress) String() string {
	return fmt.Sprintf("%s (%s)", n.Addr, n.DeviceName)
}

var (
	NodeAddressTableName statedb.TableName = "node-addresses"

	NodeAddressIndex = statedb.Index[NodeAddress, netip.Addr]{
		Name: "id",
		FromObject: func(a NodeAddress) index.KeySet {
			return index.NewKeySet(index.NetIPAddr(a.Addr))
		},
		FromKey: func(addr netip.Addr) []byte {
			return index.NetIPAddr(addr)
		},
		Unique: true,
	}

	// NodeAddressTestTableCell provides the node address Table and RWTable
	// for use in tests of modules that depend on node addresses.
	NodeAddressTestTableCell = statedb.NewTableCell[NodeAddress](
		NodeAddressTableName,
		NodeAddressIndex,
	)

	NodeAddressCell = cell.Module(
		"node-address",
		"Table of node addresses derived from system network devices",

		statedb.NewPrivateRWTableCell[NodeAddress](NodeAddressTableName, NodeAddressIndex),
		cell.Provide(
			newNodeAddressTable,
			newAddressScopeMax,
		),
		cell.Config(NodeAddressConfig{}),
	)
)

type NodeAddressConfig struct {
	NodePortAddresses []*cidr.CIDR `mapstructure:"nodeport-addresses"`

	// AddressScopeMax controls the maximum address scope for addresses to be
	// considered local ones. Affects which addresses are used for NodePort
	// and which have HOST_ID in the ipcache.
	AddressScopeMax string `mapstructure:"local-max-addr-scope"`
}

const (
	addressScopeMaxFlag = "local-max-addr-scope"
)

type AddressScopeMax uint8

func newAddressScopeMax(cfg NodeAddressConfig) (AddressScopeMax, error) {
	scope, err := ip.ParseScope(cfg.AddressScopeMax)
	if err != nil {
		return 0, fmt.Errorf("Cannot parse scope integer from --%s option", addressScopeMaxFlag)
	}
	return AddressScopeMax(scope), nil
}

func (cfg NodeAddressConfig) getNets() []*net.IPNet {
	nets := make([]*net.IPNet, len(cfg.NodePortAddresses))
	for i, cidr := range cfg.NodePortAddresses {
		nets[i] = cidr.IPNet
	}
	return nets
}

func (NodeAddressConfig) Flags(flags *pflag.FlagSet) {
	flags.StringSlice(
		"nodeport-addresses",
		nil,
		"A whitelist of CIDRs to limit which IPs are used for NodePort. If not set, primary IPv4 and/or IPv6 address of each native device is used.")

	flags.String(addressScopeMaxFlag, fmt.Sprintf("%d", defaults.AddressScopeMax), "Maximum local address scope for ipcache to consider host addresses")
	flags.MarkHidden(addressScopeMaxFlag)
}

type nodeAddressSource struct {
	cell.In

	HealthScope     cell.Scope
	Log             logrus.FieldLogger
	Config          NodeAddressConfig
	Lifecycle       hive.Lifecycle
	Jobs            job.Registry
	DB              *statedb.DB
	Devices         statedb.Table[*Device]
	NodeAddresses   statedb.RWTable[NodeAddress]
	AddressScopeMax AddressScopeMax
}

func newNodeAddressTable(n nodeAddressSource) (tbl statedb.Table[NodeAddress], err error) {
	n.register()
	return n.NodeAddresses, nil
}

func (n *nodeAddressSource) register() {
	g := n.Jobs.NewGroup(n.HealthScope)
	g.Add(job.OneShot("node-address-update", n.run))

	n.Lifecycle.Append(
		hive.Hook{
			OnStart: func(ctx hive.HookContext) error {
				// Do an immediate update to populate the table
				// before it is read from.
				n.update(ctx)

				// Start the background refresh.
				return g.Start(ctx)
			},
			OnStop: g.Stop,
		})

}

func (n *nodeAddressSource) run(ctx context.Context, reporter cell.HealthReporter) error {
	limiter := rate.NewLimiter(100*time.Millisecond, 1)
	for {
		watch, addrs := n.update(ctx)
		reporter.OK(addrs)
		select {
		case <-ctx.Done():
			return nil
		case <-watch:
		}
		if err := limiter.Wait(ctx); err != nil {
			return err
		}
	}
}

func (n *nodeAddressSource) update(ctx context.Context) (<-chan struct{}, string) {
	txn := n.DB.WriteTxn(n.NodeAddresses)
	defer txn.Abort()

	old := n.getCurrentAddresses(txn)
	new, watch := n.getAddressesFromDevices(txn)
	updated := false

	// Insert new addresses that did not exist.
	for addr := range new.Difference(old) {
		updated = true
		n.NodeAddresses.Insert(txn, addr)
	}

	// Remove addresses that were not part of the new set.
	for addr := range old.Difference(new) {
		updated = true
		n.NodeAddresses.Delete(txn, addr)
	}

	addrs := showAddresses(new)
	if updated {
		n.Log.WithField("node-addresses", addrs).Info("Node addresses updated")
		txn.Commit()
	}
	return watch, addrs
}

func (n *nodeAddressSource) getCurrentAddresses(txn statedb.ReadTxn) sets.Set[NodeAddress] {
	addrs := sets.New[NodeAddress]()
	iter, _ := n.NodeAddresses.All(txn)
	for addr, _, ok := iter.Next(); ok; addr, _, ok = iter.Next() {
		addrs.Insert(addr)
	}
	return addrs
}

func (n *nodeAddressSource) getAddressesFromDevices(txn statedb.ReadTxn) (sets.Set[NodeAddress], <-chan struct{}) {
	addrs := sets.New[NodeAddress]()

	// FIXME: This will wake up pretty often and there may be a lot of devices
	// (lxcs). Possible solutions:
	// - Table[DeviceAddress]
	// - Index based on whether the device is interesting or not.
	// - Heavy rate limiting.
	// - Or benchmark and see if it's cheap enough to iterate 10k devices every
	//   few hundred millis.

	devices, watch := n.Devices.All(txn)
	for dev, _, ok := devices.Next(); ok; dev, _, ok = devices.Next() {
		if dev.Flags&net.FlagUp == 0 {
			continue
		}

		// TODO: How to choose which devices to consider? Earlier code
		// (listLocalAddresses) was not picky, except for "docker".
		// We do need to also pick addresses from "cilium_host" here in order
		// for the address there to have HOST_ID identity.

		if strings.HasPrefix(dev.Name, "lxc") || strings.HasPrefix(dev.Name, "docker") {
			continue
		}

		// ipv4 and ipv6 are set to true when the primary address is picked.
		ipv4, ipv6 := false, false

		// The addresses are sorted by scope so global primary addresses come first.
		for _, addr := range sortAddresses(dev.Addrs) {
			// Keep the scope-based address filtering as was introduced
			// in 080857bdedca67d58ec39f8f96c5f38b22f6dc0b.
			if addr.Scope > uint8(n.AddressScopeMax) {
				// Addresses are sorted by scope, so can stop early.
				break
			}
			if addr.Addr.IsLoopback() {
				continue
			}

			nodePort := false
			primary := false
			if len(n.Config.NodePortAddresses) == 0 {
				// The user has not specified IP ranges to filter on IPs on which to serve NodePort.
				// Thus the default behavior is to use the primary IPv4 and IPv6 addresses of each
				// device.
				if addr.Addr.Is4() && !ipv4 {
					ipv4 = true
					nodePort = true
					primary = true
				}
				if addr.Addr.Is6() && !ipv6 {
					ipv6 = true
					nodePort = true
					primary = true
				}
			} else if ip.NetsContainsAny(n.Config.getNets(), []*net.IPNet{ip.IPToPrefix(addr.AsIP())}) {
				nodePort = true
				if addr.Addr.Is4() && !ipv4 {
					primary = true
					ipv4 = true
				} else if addr.Addr.Is6() && !ipv6 {
					primary = true
					ipv6 = true
				}
			}
			addrs.Insert(NodeAddress{Addr: addr.Addr, Primary: primary, NodePort: nodePort, DeviceName: dev.Name})
		}
	}
	return addrs, watch
}

// showAddresses formats a Set[NodeAddress] as "1.2.3.4 (eth0), fe80::1 (eth1)"
func showAddresses(addrs sets.Set[NodeAddress]) string {
	ss := make([]string, 0, len(addrs))
	for addr := range addrs {
		ss = append(ss, addr.String())
	}
	sort.Strings(ss)
	return strings.Join(ss, ", ")
}

// sortAddresses returns a copy of the addresses, sorted by primary (e.g. !iIFA_F_SECONDARY) and then by
// address scope.
func sortAddresses(addrs []DeviceAddress) []DeviceAddress {
	addrs = slices.Clone(addrs)

	sort.SliceStable(addrs, func(i, j int) bool {
		switch {
		case addrs[i].Primary && !addrs[j].Primary:
			return true
		case !addrs[i].Primary && addrs[j].Primary:
			return false
		default:
			return addrs[i].Scope < addrs[j].Scope
		}
	})
	return addrs
}
