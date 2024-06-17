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

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"
	"github.com/cilium/statedb/index"
	"github.com/sirupsen/logrus"
	"github.com/spf13/pflag"
	"k8s.io/apimachinery/pkg/util/sets"

	"github.com/cilium/cilium/pkg/cidr"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/ip"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/rate"
	"github.com/cilium/cilium/pkg/time"
)

// WildcardDeviceName for looking up a fallback global address. This is used for
// picking a BPF masquerade or direct routing address in cases where the target
// device doesn't have an IP address (ECMP and similar setups).
const WildcardDeviceName = "*"

// NodeAddress is an IP address assigned to a network interface on a Cilium node
// that is considered a "host" IP address.
type NodeAddress struct {
	Addr netip.Addr

	// NodePort is true if this address is to be used for NodePort.
	// If --nodeport-addresses is set, then all addresses on native
	// devices that are contained within the specified CIDRs are chosen.
	// If it is not set, then only the primary IPv4 and/or IPv6 address
	// of each native device is used.
	NodePort bool

	// Primary is true if this is the primary IPv4 or IPv6 address of this device.
	// This is mainly used to pick the address for BPF masquerading.
	Primary bool

	// DeviceName is the name of the network device from which this address
	// is derived from.
	DeviceName string
}

func (n *NodeAddress) IP() net.IP {
	return n.Addr.AsSlice()
}

func (n *NodeAddress) String() string {
	return fmt.Sprintf("%s (%s)", n.Addr, n.DeviceName)
}

// GetAddr returns the address. Useful when mapping over NodeAddress's with
// e.g. statedb.Map.
func (n NodeAddress) GetAddr() netip.Addr {
	return n.Addr
}

func (n NodeAddress) TableHeader() []string {
	return []string{
		"Address",
		"NodePort",
		"Primary",
		"DeviceName",
	}
}

func (n NodeAddress) TableRow() []string {
	return []string{
		n.Addr.String(),
		fmt.Sprintf("%v", n.NodePort),
		fmt.Sprintf("%v", n.Primary),
		n.DeviceName,
	}
}

type NodeAddressConfig struct {
	NodePortAddresses []*cidr.CIDR `mapstructure:"nodeport-addresses"`
}

type NodeAddressKey struct {
	Addr       netip.Addr
	DeviceName string
}

func (k NodeAddressKey) Key() index.Key {
	return append(index.NetIPAddr(k.Addr), []byte(k.DeviceName)...)
}

var (
	// NodeAddressIndex is the primary index for node addresses:
	//
	//   var nodeAddresses Table[NodeAddress]
	//   nodeAddresses.First(txn, NodeAddressIndex.Query(netip.MustParseAddr("1.2.3.4")))
	NodeAddressIndex = statedb.Index[NodeAddress, NodeAddressKey]{
		Name: "id",
		FromObject: func(a NodeAddress) index.KeySet {
			return index.NewKeySet(NodeAddressKey{a.Addr, a.DeviceName}.Key())
		},
		FromKey: NodeAddressKey.Key,
		Unique:  true,
	}

	NodeAddressDeviceNameIndex = statedb.Index[NodeAddress, string]{
		Name: "name",
		FromObject: func(a NodeAddress) index.KeySet {
			return index.NewKeySet(index.String(a.DeviceName))
		},
		FromKey: index.String,
		Unique:  false,
	}

	NodeAddressNodePortIndex = statedb.Index[NodeAddress, bool]{
		Name: "node-port",
		FromObject: func(a NodeAddress) index.KeySet {
			return index.NewKeySet(index.Bool(a.NodePort))
		},
		FromKey: index.Bool,
		Unique:  false,
	}

	NodeAddressTableName statedb.TableName = "node-addresses"

	// NodeAddressCell provides Table[NodeAddress] and a background controller
	// that derives the node addresses from the low-level Table[*Device].
	//
	// The Table[NodeAddress] contains the actual assigned addresses on the node,
	// but not for example external Kubernetes node addresses that may be merely
	// NATd to a private address. Those can be queried through [node.LocalNodeStore].
	NodeAddressCell = cell.Module(
		"node-address",
		"Table of node addresses derived from system network devices",

		cell.ProvidePrivate(NewNodeAddressTable),
		cell.Provide(
			newNodeAddressController,
			newAddressScopeMax,
		),
		cell.Config(NodeAddressConfig{}),
	)
)

func NewNodeAddressTable() (statedb.RWTable[NodeAddress], error) {
	return statedb.NewTable(
		NodeAddressTableName,
		NodeAddressIndex,
		NodeAddressDeviceNameIndex,
		NodeAddressNodePortIndex,
	)
}

const (
	nodeAddressControllerMinInterval = 100 * time.Millisecond
)

// AddressScopeMax sets the maximum scope an IP address can have. A scope
// is defined in rtnetlink(7) as the distance to the destination where a
// lower number signifies a wider scope with RT_SCOPE_UNIVERSE (0) being
// the widest.
//
// This defaults to RT_SCOPE_LINK-1 (defaults.AddressScopeMax) and can be
// set by the user with --local-max-addr-scope.
type AddressScopeMax uint8

func newAddressScopeMax(cfg NodeAddressConfig, daemonCfg *option.DaemonConfig) (AddressScopeMax, error) {
	return AddressScopeMax(daemonCfg.AddressScopeMax), nil
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
}

type nodeAddressControllerParams struct {
	cell.In

	Health          cell.Health
	Log             logrus.FieldLogger
	Config          NodeAddressConfig
	Lifecycle       cell.Lifecycle
	Jobs            job.Registry
	DB              *statedb.DB
	Devices         statedb.Table[*Device]
	NodeAddresses   statedb.RWTable[NodeAddress]
	AddressScopeMax AddressScopeMax
}

type nodeAddressController struct {
	nodeAddressControllerParams

	deviceChanges statedb.ChangeIterator[*Device]

	fallbackAddresses fallbackAddresses
}

// newNodeAddressController constructs the node address controller & registers its
// lifecycle hooks and then provides Table[NodeAddress] to the application.
// This enforces proper ordering, e.g. controller is started before anything
// that depends on Table[NodeAddress] and allows it to populate it before
// it is accessed.
func newNodeAddressController(p nodeAddressControllerParams) (tbl statedb.Table[NodeAddress], err error) {
	if err := p.DB.RegisterTable(p.NodeAddresses); err != nil {
		return nil, err
	}

	n := nodeAddressController{nodeAddressControllerParams: p}
	n.register()
	return n.NodeAddresses, nil
}

func (n *nodeAddressController) register() {
	g := n.Jobs.NewGroup(n.Health)
	g.Add(job.OneShot("node-address-update", n.run))

	n.Lifecycle.Append(
		cell.Hook{
			OnStart: func(ctx cell.HookContext) error {
				txn := n.DB.WriteTxn(n.NodeAddresses, n.Devices /* for delete tracker */)
				defer txn.Abort()

				// Start tracking deletions of devices.
				var err error
				n.deviceChanges, err = n.Devices.Changes(txn)
				if err != nil {
					return fmt.Errorf("DeleteTracker: %w", err)
				}

				// Do an immediate update to populate the table before it is read from.
				devices, _ := n.Devices.All(txn)
				for dev, _, ok := devices.Next(); ok; dev, _, ok = devices.Next() {
					n.update(txn, nil, n.getAddressesFromDevice(dev), nil, dev.Name)
					n.updateWildcardDevice(txn, dev, false)
				}
				txn.Commit()

				// Start the job in the background to incremental refresh
				// the node addresses.
				return g.Start(ctx)
			},
			OnStop: g.Stop,
		})

}

func (n *nodeAddressController) run(ctx context.Context, reporter cell.Health) error {
	defer n.deviceChanges.Close()

	limiter := rate.NewLimiter(nodeAddressControllerMinInterval, 1)
	for {
		txn := n.DB.WriteTxn(n.NodeAddresses)
		for change, _, ok := n.deviceChanges.Next(); ok; change, _, ok = n.deviceChanges.Next() {
			dev := change.Object

			// Note: prefix match! existing may contain node addresses from devices with names
			// prefixed by dev. See https://github.com/cilium/cilium/issues/29324.
			addrIter := n.NodeAddresses.List(txn, NodeAddressDeviceNameIndex.Query(dev.Name))
			existing := statedb.Collect(addrIter)
			var new sets.Set[NodeAddress]
			if !change.Deleted {
				new = n.getAddressesFromDevice(dev)
			}
			n.update(txn, sets.New(existing...), new, reporter, dev.Name)
			n.updateWildcardDevice(txn, dev, change.Deleted)
		}
		txn.Commit()

		select {
		case <-ctx.Done():
			return nil
		case <-n.deviceChanges.Watch(n.DB.ReadTxn()):
		}
		if err := limiter.Wait(ctx); err != nil {
			return err
		}
	}
}

// updateWildcardDevice updates the wildcard device ("*") with the fallback addresses. The fallback
// addresses are the most suitable IPv4 and IPv6 address on any network device, whether it's
// selected for datapath use or not.
func (n *nodeAddressController) updateWildcardDevice(txn statedb.WriteTxn, dev *Device, deleted bool) {
	if !n.updateFallbacks(txn, dev, deleted) {
		// No changes
		return
	}

	// Clear existing fallback addresses.
	iter := n.NodeAddresses.List(txn, NodeAddressDeviceNameIndex.Query(WildcardDeviceName))
	for addr, _, ok := iter.Next(); ok; addr, _, ok = iter.Next() {
		n.NodeAddresses.Delete(txn, addr)
	}

	newAddrs := sets.New[NodeAddress]()
	for _, fallback := range n.fallbackAddresses.addrs() {
		if !fallback.IsValid() {
			continue
		}
		nodeAddr := NodeAddress{
			Addr:       fallback,
			NodePort:   false,
			Primary:    true,
			DeviceName: WildcardDeviceName,
		}
		newAddrs.Insert(nodeAddr)
		n.NodeAddresses.Insert(txn, nodeAddr)
	}

	n.Log.WithFields(logrus.Fields{"node-addresses": showAddresses(newAddrs), logfields.Device: WildcardDeviceName}).Info("Fallback node addresses updated")
}

func (n *nodeAddressController) updateFallbacks(txn statedb.ReadTxn, dev *Device, deleted bool) (updated bool) {
	if dev.Name == defaults.HostDevice {
		return false
	}

	fallbacks := &n.fallbackAddresses
	if deleted && (fallbacks.ipv4.dev == dev || fallbacks.ipv6.dev == dev) {
		// The device that was used for fallback address was removed.
		// Clear the fallbacks and reprocess from scratch.
		fallbacks.clear()
		devices, _ := n.Devices.All(txn)
		for dev, _, ok := devices.Next(); ok; dev, _, ok = devices.Next() {
			fallbacks.update(dev)
		}
		return true
	} else {
		return n.fallbackAddresses.update(dev)
	}
}

// updates the node addresses of a single device.
func (n *nodeAddressController) update(txn statedb.WriteTxn, existing, new sets.Set[NodeAddress], reporter cell.Health, device string) {
	updated := false
	prefixLen := len(device)

	// Insert new addresses that did not exist.
	for addr := range new {
		if !existing.Has(addr) {
			updated = true
			n.NodeAddresses.Insert(txn, addr)
		}
	}

	// Remove addresses that were not part of the new set.
	for addr := range existing {
		// Ensure full device name match. 'device' may be a prefix of DeviceName, and we don't want
		// to delete node addresses of `cilium_host` because they are not on `cilium`.
		if prefixLen != len(addr.DeviceName) {
			continue
		}

		if !new.Has(addr) {
			updated = true
			n.NodeAddresses.Delete(txn, addr)
		}
	}

	if updated {
		addrs := showAddresses(new)
		n.Log.WithFields(logrus.Fields{"node-addresses": addrs, logfields.Device: device}).Info("Node addresses updated")
		if reporter != nil {
			reporter.OK(addrs)
		}
	}
}

func (n *nodeAddressController) getAddressesFromDevice(dev *Device) sets.Set[NodeAddress] {
	if dev.Flags&net.FlagUp == 0 {
		return nil
	}

	if dev.Name != defaults.HostDevice {
		// Only take addresses from the selected devices.
		if !dev.Selected {
			return nil
		}

		// Skip obviously uninteresting devices. We include the HostDevice as its IP addresses are
		// considered node addresses and added to e.g. ipcache as HOST_IDs.
		for _, prefix := range defaults.ExcludedDevicePrefixes {
			if strings.HasPrefix(dev.Name, prefix) {
				return nil
			}
		}
	}

	addrs := make([]NodeAddress, 0, len(dev.Addrs))

	// ipv4Found and ipv6Found are set to true when the primary address is picked
	// (used for the Primary flag)
	ipv4Found, ipv6Found := false, false

	// The indexes for the first public and private addresses for picking NodePort
	// addresses.
	ipv4PublicIndex, ipv4PrivateIndex := -1, -1
	ipv6PublicIndex, ipv6PrivateIndex := -1, -1

	// Do a first pass to pick the addresses.
	for _, addr := range SortedAddresses(dev.Addrs) {
		// We keep the scope-based address filtering as was introduced
		// in 080857bdedca67d58ec39f8f96c5f38b22f6dc0b.
		skip := addr.Scope > RouteScope(n.AddressScopeMax) || addr.Addr.IsLoopback()

		// Always include LINK scope'd addresses for cilium_host device, regardless
		// of what the maximum scope is.
		skip = skip && !(dev.Name == defaults.HostDevice && addr.Scope == RT_SCOPE_LINK)

		if skip {
			continue
		}

		// index to which this address is appended.
		index := len(addrs)

		isPublic := ip.IsPublicAddr(addr.Addr.AsSlice())
		primary := false
		if addr.Addr.Is4() {
			if !ipv4Found {
				ipv4Found = true
				primary = true
			}
			if ipv4PublicIndex < 0 && isPublic {
				ipv4PublicIndex = index
			}
			if ipv4PrivateIndex < 0 && !isPublic {
				ipv4PrivateIndex = index
			}
		}

		if addr.Addr.Is6() {
			if !ipv6Found {
				ipv6Found = true
				primary = true
			}

			if ipv6PublicIndex < 0 && isPublic {
				ipv6PublicIndex = index
			}
			if ipv6PrivateIndex < 0 && !isPublic {
				ipv6PrivateIndex = index
			}
		}

		// If the user has specified --nodeport-addresses use the addresses within the range for
		// NodePort. If not, the first private (or public if private not found) will be picked
		// by the logic following this loop.
		nodePort := false
		if len(n.Config.NodePortAddresses) > 0 {
			nodePort = dev.Selected && ip.NetsContainsAny(n.Config.getNets(), []*net.IPNet{ip.IPToPrefix(addr.AsIP())})
		}
		addrs = append(addrs,
			NodeAddress{
				Addr:       addr.Addr,
				Primary:    primary,
				NodePort:   nodePort,
				DeviceName: dev.Name,
			})
	}

	if len(n.Config.NodePortAddresses) == 0 && dev.Selected {
		// Pick the NodePort addresses. Prefer private addresses if possible.
		if ipv4PrivateIndex >= 0 {
			addrs[ipv4PrivateIndex].NodePort = true
		} else if ipv4PublicIndex >= 0 {
			addrs[ipv4PublicIndex].NodePort = true
		}

		if ipv6PrivateIndex >= 0 {
			addrs[ipv6PrivateIndex].NodePort = true
		} else if ipv6PublicIndex >= 0 {
			addrs[ipv6PublicIndex].NodePort = true
		}
	}

	return sets.New(addrs...)
}

// showAddresses formats a Set[NodeAddress] as "1.2.3.4 (primary, nodeport), fe80::1"
func showAddresses(addrs sets.Set[NodeAddress]) string {
	ss := make([]string, 0, len(addrs))
	for addr := range addrs {
		var extras []string
		if addr.Primary {
			extras = append(extras, "primary")
		}
		if addr.NodePort {
			extras = append(extras, "nodeport")
		}
		if extras != nil {
			ss = append(ss, fmt.Sprintf("%s (%s)", addr.Addr, strings.Join(extras, ", ")))
		} else {
			ss = append(ss, addr.Addr.String())
		}
	}
	sort.Strings(ss)
	return strings.Join(ss, ", ")
}

// sortedAddresses returns a copy of the addresses sorted by following predicates
// (first predicate matching in this order wins):
// - Primary (e.g. !IFA_F_SECONDARY)
// - Scope, with lower scope going first (e.g. UNIVERSE before LINK)
// - Public addresses before private (e.g. 1.2.3.4 before 192.168.1.1)
// - By address itself (192.168.1.1 before 192.168.1.2)
//
// The sorting order affects which address is marked 'Primary' and which is picked as
// the 'NodePort' address (when --nodeport-addresses is not specified).
func SortedAddresses(addrs []DeviceAddress) []DeviceAddress {
	addrs = slices.Clone(addrs)

	sort.SliceStable(addrs, func(i, j int) bool {
		switch {
		case !addrs[i].Secondary && addrs[j].Secondary:
			return true
		case addrs[i].Secondary && !addrs[j].Secondary:
			return false
		case addrs[i].Scope < addrs[j].Scope:
			return true
		case addrs[i].Scope > addrs[j].Scope:
			return false
		case ip.IsPublicAddr(addrs[i].Addr.AsSlice()) && !ip.IsPublicAddr(addrs[j].Addr.AsSlice()):
			return true
		case !ip.IsPublicAddr(addrs[i].Addr.AsSlice()) && ip.IsPublicAddr(addrs[j].Addr.AsSlice()):
			return false
		default:
			return addrs[i].Addr.Less(addrs[j].Addr)
		}
	})
	return addrs
}

type fallbackAddress struct {
	dev  *Device
	addr DeviceAddress
}

type fallbackAddresses struct {
	ipv4 fallbackAddress
	ipv6 fallbackAddress
}

func (f *fallbackAddresses) clear() {
	f.ipv4 = fallbackAddress{}
	f.ipv6 = fallbackAddress{}
}

func (f *fallbackAddresses) addrs() []netip.Addr {
	return []netip.Addr{f.ipv4.addr.Addr, f.ipv6.addr.Addr}
}

func (f *fallbackAddresses) update(dev *Device) (updated bool) {
	// Iterate over all addresses to see if any of them make for a better
	// fallback address.
	for _, addr := range dev.Addrs {
		if addr.Secondary {
			continue
		}
		fa := &f.ipv4
		if addr.Addr.Is6() {
			fa = &f.ipv6
		}
		better := false
		switch {
		case fa.dev == nil:
			better = true
		case ip.IsPublicAddr(addr.Addr.AsSlice()) && !ip.IsPublicAddr(fa.addr.Addr.AsSlice()):
			better = true
		case !ip.IsPublicAddr(addr.Addr.AsSlice()) && ip.IsPublicAddr(fa.addr.Addr.AsSlice()):
			better = false
		case addr.Scope < fa.addr.Scope:
			better = true
		case addr.Scope > fa.addr.Scope:
			better = false
		case dev.Index < fa.dev.Index:
			better = true
		case dev.Index > fa.dev.Index:
			better = false
		default:
			better = addr.Addr.Less(fa.addr.Addr)
		}
		if better {
			updated = true
			fa.dev = dev
			fa.addr = addr
		}
	}
	return
}

// Shared test address definitions
var (
	TestIPv4InternalAddress = netip.MustParseAddr("10.0.0.2")
	TestIPv4NodePortAddress = netip.MustParseAddr("10.0.0.3")
	TestIPv6InternalAddress = netip.MustParseAddr("f00d::1")
	TestIPv6NodePortAddress = netip.MustParseAddr("f00d::2")

	TestAddresses = []NodeAddress{
		{
			Addr:       TestIPv4InternalAddress,
			NodePort:   true,
			Primary:    true,
			DeviceName: "test",
		},
		{
			Addr:       TestIPv4NodePortAddress,
			NodePort:   true,
			Primary:    false,
			DeviceName: "test",
		},
		{
			Addr:       TestIPv6InternalAddress,
			NodePort:   true,
			Primary:    true,
			DeviceName: "test",
		},
		{
			Addr:       TestIPv6NodePortAddress,
			NodePort:   true,
			Primary:    false,
			DeviceName: "test",
		},
	}
)
