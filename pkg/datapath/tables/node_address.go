// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package tables

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"slices"
	"sort"
	"strings"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"
	"github.com/cilium/statedb/index"
	"github.com/spf13/pflag"
	"k8s.io/apimachinery/pkg/util/sets"

	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/ip"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/node/addressing"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/time"
)

// WildcardDeviceName for looking up a fallback global address. This is used for
// picking a BPF masquerade or direct routing address in cases where the target
// device doesn't have an IP address (ECMP and similar setups).
const WildcardDeviceName = "*"

// NodeAddress is an IP address assigned to a network interface on a Cilium node
// that is considered a "host" IP address.
//
// NOTE: Update DeepEqual() when this struct is modified
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

func (n *NodeAddress) DeepEqual(other *NodeAddress) bool {
	return n.Addr == other.Addr &&
		n.NodePort == other.NodePort &&
		n.Primary == other.Primary &&
		n.DeviceName == other.DeviceName
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
	NodePortAddresses []netip.Prefix `mapstructure:"nodeport-addresses"`
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
		FromString: func(key string) (index.Key, error) {
			addrS, device, _ := strings.Cut(key, "/")
			addr, err := netip.ParseAddr(addrS)
			if err != nil {
				return index.Key{}, nil
			}
			return NodeAddressKey{Addr: addr, DeviceName: device}.Key(), nil
		},
		Unique: true,
	}

	NodeAddressDeviceNameIndex = statedb.Index[NodeAddress, string]{
		Name: "name",
		FromObject: func(a NodeAddress) index.KeySet {
			return index.NewKeySet(index.String(a.DeviceName))
		},
		FromKey:    index.String,
		FromString: index.FromString,
		Unique:     false,
	}

	NodeAddressNodePortIndex = statedb.Index[NodeAddress, bool]{
		Name: "node-port",
		FromObject: func(a NodeAddress) index.KeySet {
			return index.NewKeySet(index.Bool(a.NodePort))
		},
		FromKey:    index.Bool,
		FromString: index.BoolString,
		Unique:     false,
	}

	NodeAddressTableName statedb.TableName = "node-addresses"

	// NodeAddressCell provides Table[NodeAddress] and a background controller
	// that derives the node addresses from the low-level Table[*Device].
	//
	// The Table[NodeAddress] contains the actual assigned addresses on the node,
	// but not for example external Kubernetes node addresses that may be merely
	// NATd to a private address. Those can be queried through Table[*node.LocalNode].
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

func NewNodeAddressTable(db *statedb.DB) (statedb.RWTable[NodeAddress], error) {
	return statedb.NewTable(
		db,
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
// This defaults to RT_SCOPE_HOST (defaults.AddressScopeMax) and can be
// set by the user with --local-max-addr-scope.
type AddressScopeMax uint8

func newAddressScopeMax(cfg NodeAddressConfig, daemonCfg *option.DaemonConfig) (AddressScopeMax, error) {
	return AddressScopeMax(daemonCfg.AddressScopeMax), nil
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
	Log             *slog.Logger
	Config          NodeAddressConfig
	Lifecycle       cell.Lifecycle
	Jobs            job.Group
	DB              *statedb.DB
	Devices         statedb.Table[*Device]
	Routes          statedb.Table[*Route]
	NodeAddresses   statedb.RWTable[NodeAddress]
	AddressScopeMax AddressScopeMax
	Nodes           statedb.Table[*node.LocalNode]
}

type nodeAddressController struct {
	nodeAddressControllerParams

	fallbackAddresses fallbackAddresses
}

// newNodeAddressController constructs the node address controller & registers its
// lifecycle hooks and then provides Table[NodeAddress] to the application.
// This enforces proper ordering, e.g. controller is started before anything
// that depends on Table[NodeAddress] and allows it to populate it before
// it is accessed.
func newNodeAddressController(p nodeAddressControllerParams) (tbl statedb.Table[NodeAddress], err error) {
	n := nodeAddressController{nodeAddressControllerParams: p}
	n.register()
	return n.NodeAddresses, nil
}

func (n *nodeAddressController) register() {
	n.Lifecycle.Append(
		cell.Hook{
			OnStart: func(ctx cell.HookContext) error {
				// Perform an initial synchronous reconciliation to populate the table.
				// This ensures that dependent cells see the initial state when they start.
				// The watch channels returned here will be the initial channels for the run loop.
				ws := n.reconcile()

				// Start the background job for continuous reconciliation.
				n.Jobs.Add(job.OneShot("node-address-update", func(ctx context.Context, reporter cell.Health) error {
					return n.run(ctx, ws)
				}))
				return nil
			},
		})
}

func (n *nodeAddressController) run(ctx context.Context, ws *statedb.WatchSet) error {
	for {
		// Wait for changes
		closedChannels, err := ws.Wait(ctx, nodeAddressControllerMinInterval)
		if err != nil {
			return nil
		}
		if len(closedChannels) > 0 {
			// Perform the full reconciliation and get new watch set
			ws = n.reconcile()
		}
	}
}

// reconcile performs a full reconciliation of the NodeAddress table. It computes
// the desired state from the Devices table and updates the NodeAddress table
// to match it. It returns the read transaction and new watch channels for Devices and Routes.
func (n *nodeAddressController) reconcile() *statedb.WatchSet {
	ws := statedb.NewWatchSet()

	rtxn := n.DB.ReadTxn()

	var k8sIPv4, k8sIPv6 netip.Addr
	if localNode, _, watch, found := n.Nodes.GetWatch(rtxn, node.LocalNodeQuery); found {
		k8sIPv4, _ = netip.AddrFromSlice(addressing.ExtractNodeIP[nodeTypes.Address](localNode.IPAddresses, false))
		k8sIPv6, _ = netip.AddrFromSlice(addressing.ExtractNodeIP[nodeTypes.Address](localNode.IPAddresses, true))
		ws.Add(watch)
	}

	// Get iterators for the current state and new watch channels.
	allDevices, devicesWatch := n.Devices.AllWatch(rtxn)
	ws.Add(devicesWatch)
	localRoutes, routesWatch := n.Routes.PrefixWatch(rtxn, RouteIDIndex.Query(RouteID{Table: RT_TABLE_LOCAL}))
	ws.Add(routesWatch)

	// A map to hold the desired state of node addresses, keyed by device name.
	newAddrsByDevice := make(map[string][]NodeAddress)
	addrsFound := sets.New[netip.Addr]()

	// Get addresses from devices
	n.fallbackAddresses.clear()
	for dev := range allDevices {
		deviceAddrs := n.getAddressesFromDevice(dev, k8sIPv4, k8sIPv6)
		if deviceAddrs == nil {
			continue
		}
		newAddrsByDevice[dev.Name] = deviceAddrs
		for _, addr := range deviceAddrs {
			addrsFound.Insert(addr.Addr)
		}

		// Update fallback address candidates. lxc and cilium_host devices are ignored.
		if !strings.HasPrefix(dev.Name, "lxc") && dev.Name != defaults.HostDevice {
			n.fallbackAddresses.update(dev)
		}
	}

	for route := range localRoutes {
		// We are only interested in local routes, which are used for IPs that are assigned
		// to the host (e.g. on GCE). These routes are in the local table, have host scope,
		// and have no source address.
		if route.Scope != RT_SCOPE_HOST || route.Src.IsValid() {
			continue
		}

		dst := route.Dst
		if !dst.IsValid() || dst.Addr().IsUnspecified() || dst.Addr().IsLoopback() {
			continue
		}

		if addrsFound.Has(dst.Addr()) {
			continue
		}

		dev, _, found := n.Devices.Get(rtxn, DeviceIDIndex.Query(route.LinkIndex))
		if !found {
			continue
		}

		if !n.shouldUseDeviceForNodeAddress(dev) {
			continue
		}

		nodePort := false
		if len(n.Config.NodePortAddresses) > 0 {
			nodePort = dev.Name != defaults.HostDevice && ip.PrefixesContains(n.Config.NodePortAddresses, dst.Addr())

		}
		nodeAddr := NodeAddress{
			Addr:       dst.Addr(),
			NodePort:   nodePort,
			Primary:    true, // Preferred source on a route is a strong candidate for a primary address.
			DeviceName: dev.Name,
		}
		newAddrsByDevice[dev.Name] = append(newAddrsByDevice[dev.Name], nodeAddr)
		addrsFound.Insert(dst.Addr())
	}

	// Derive wildcard addresses from fallback candidates
	var wildcardAddrs []NodeAddress
	for _, fallback := range n.fallbackAddresses.addrs() {
		if fallback.IsValid() {
			wildcardAddrs = append(wildcardAddrs, NodeAddress{
				Addr:       fallback,
				NodePort:   false,
				Primary:    true,
				DeviceName: WildcardDeviceName,
			})
		}
	}

	if len(wildcardAddrs) > 0 {
		newAddrsByDevice[WildcardDeviceName] = wildcardAddrs
		n.Log.Info(
			"Fallback node addresses updated",
			logfields.Addresses, showAddresses(wildcardAddrs),
			logfields.Device, WildcardDeviceName,
		)
	}

	wtxn := n.DB.WriteTxn(n.NodeAddresses)
	defer wtxn.Abort()

	// Apply changes to the NodeAddress table
	devicesWithAddrs := sets.New[string]()
	for addr := range n.NodeAddresses.All(wtxn) {
		devicesWithAddrs.Insert(addr.DeviceName)
	}

	for devName, addrs := range newAddrsByDevice {
		n.update(wtxn, addrs, n.Health, devName)
		devicesWithAddrs.Delete(devName)
	}

	for deletedDevName := range devicesWithAddrs {
		n.update(wtxn, nil, n.Health, deletedDevName)
	}
	wtxn.Commit()
	return ws
}

// updates the node addresses of a single device.
func (n *nodeAddressController) update(txn statedb.WriteTxn, new []NodeAddress, reporter cell.Health, device string) {
	updated := false

	// Gather the set of currently existing addresses for this device.
	current := sets.New(statedb.Collect(
		statedb.Map(
			n.NodeAddresses.List(txn, NodeAddressDeviceNameIndex.Query(device)),
			func(addr NodeAddress) netip.Addr {
				return addr.Addr
			}))...)

	// Update the new set of addresses for this device. We try to avoid insertions when nothing has changed
	// to avoid unnecessary wakeups to watchers of the table.
	for _, addr := range new {
		old, _, hadOld := n.NodeAddresses.Get(txn, NodeAddressIndex.Query(NodeAddressKey{Addr: addr.Addr, DeviceName: device}))
		if !hadOld || old != addr {
			updated = true
			n.NodeAddresses.Insert(txn, addr)
		}
		current.Delete(addr.Addr)
	}

	// Delete the addresses no longer associated with the device.
	for addr := range current {
		updated = true
		n.NodeAddresses.Delete(txn, NodeAddress{DeviceName: device, Addr: addr})
	}

	if updated {
		addrs := showAddresses(new)
		n.Log.Info(
			"Node addresses updated",
			logfields.Addresses, addrs,
			logfields.Device, device,
		)
		if reporter != nil {
			reporter.OK(addrs)
		}
	}
}

// whiteListDevices are the devices from which node IPs are taken from regardless
// of whether they are selected or not.
var whitelistDevices = []string{
	defaults.HostDevice,
	"lo",
}

func (n *nodeAddressController) shouldUseDeviceForNodeAddress(dev *Device) bool {
	// Don't exclude addresses attached to dummy devices, since they may be setup by
	// processes like nodelocaldns, and these devices aren't always brought up. See
	// https://github.com/kubernetes/dns/blob/fa0192f004c9571cf24d8e9868be07f57380fccb/pkg/netif/netif.go#L24-L36
	// Failure to include these addresses in node addresses will trigger fib_lookup
	// when bpf host routing is enabled and result in packet drops.
	if dev.Type != "dummy" && dev.Flags&net.FlagUp == 0 {
		return false
	}

	// Ignore non-whitelisted & non-selected devices.
	if !slices.Contains(whitelistDevices, dev.Name) && (!dev.Selected && dev.Type != "dummy") {
		return false
	}

	return true
}

func (n *nodeAddressController) getAddressesFromDevice(dev *Device, k8sIPv4, k8sIPv6 netip.Addr) []NodeAddress {
	if !n.shouldUseDeviceForNodeAddress(dev) {
		return nil
	}

	addrs := make([]NodeAddress, 0, len(dev.Addrs))

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
		if addr.Addr.Is4() {
			if addr.Addr.Unmap() == k8sIPv4.Unmap() {
				// Address matches the K8s Node IP. Prioritize it within its
				// category (public or private) for NodePort address selection.
				// We don't force it to both categories, as that would break
				// the "prefer public over private" logic for Primary address
				// selection used by BPF masquerading.
				// See: https://github.com/cilium/cilium/issues/41866
				if isPublic {
					ipv4PublicIndex = index
				} else {
					ipv4PrivateIndex = index
				}
			}
			if ipv4PublicIndex < 0 && isPublic {
				ipv4PublicIndex = index
			}
			if ipv4PrivateIndex < 0 && !isPublic {
				ipv4PrivateIndex = index
			}
		}

		if addr.Addr.Is6() {
			if addr.Addr == k8sIPv6 {
				// Address matches the K8s Node IP. Prioritize it within its
				// category (public or private) for NodePort address selection.
				// We don't force it to both categories, as that would break
				// the "prefer public over private" logic for Primary address
				// selection used by BPF masquerading.
				// See: https://github.com/cilium/cilium/issues/41866
				if isPublic {
					ipv6PublicIndex = index
				} else {
					ipv6PrivateIndex = index
				}
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
			nodePort = dev.Name != defaults.HostDevice && ip.PrefixesContains(n.Config.NodePortAddresses, addr.Addr)
		}
		addrs = append(addrs,
			NodeAddress{
				Addr:       addr.Addr,
				NodePort:   nodePort,
				DeviceName: dev.Name,
			})
	}

	if len(n.Config.NodePortAddresses) == 0 && dev.Name != defaults.HostDevice && dev.Flags&net.FlagUp != 0 {
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

	// Pick the primary address. Prefer public over private.
	if ipv4PublicIndex >= 0 {
		addrs[ipv4PublicIndex].Primary = true
	} else if ipv4PrivateIndex >= 0 {
		addrs[ipv4PrivateIndex].Primary = true
	}
	if ipv6PublicIndex >= 0 {
		addrs[ipv6PublicIndex].Primary = true
	} else if ipv6PrivateIndex >= 0 {
		addrs[ipv6PrivateIndex].Primary = true
	}

	return addrs
}

// showAddresses formats a Set[NodeAddress] as "1.2.3.4 (primary, nodeport), fe80::1"
func showAddresses(addrs []NodeAddress) string {
	ss := make([]string, 0, len(addrs))
	for _, addr := range addrs {
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
	slices.Sort(ss)
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
	prevIPv4, prevIPv6 := f.ipv4.addr, f.ipv6.addr

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
		case dev.Selected && !fa.dev.Selected:
			better = true
		case !dev.Selected && fa.dev.Selected:
			better = false
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
			fa.dev = dev
			fa.addr = addr
		}
	}
	return prevIPv4 != f.ipv4.addr || prevIPv6 != f.ipv6.addr
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
