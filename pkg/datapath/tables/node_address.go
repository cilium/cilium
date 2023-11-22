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

	"github.com/sirupsen/logrus"
	"github.com/spf13/pflag"
	"golang.org/x/sys/unix"
	"k8s.io/apimachinery/pkg/util/sets"

	"github.com/cilium/cilium/pkg/cidr"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/hive/job"
	"github.com/cilium/cilium/pkg/ip"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/rate"
	"github.com/cilium/cilium/pkg/statedb"
	"github.com/cilium/cilium/pkg/statedb/index"
	"github.com/cilium/cilium/pkg/time"
)

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

type NodeAddressConfig struct {
	NodePortAddresses []*cidr.CIDR `mapstructure:"nodeport-addresses"`
}

var (
	// NodeAddressIndex is the primary index for node addresses:
	//
	//   var nodeAddresses Table[NodeAddress]
	//   nodeAddresses.First(txn, NodeAddressIndex.Query(netip.MustParseAddr("1.2.3.4")))
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

	NodeAddressDeviceNameIndex = statedb.Index[NodeAddress, string]{
		Name: "name",
		FromObject: func(a NodeAddress) index.KeySet {
			return index.NewKeySet(index.String(a.DeviceName))
		},
		FromKey: index.String,
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
	return statedb.NewTable[NodeAddress](
		NodeAddressTableName,
		NodeAddressIndex,
		NodeAddressDeviceNameIndex,
	)
}

const (
	nodeAddressControllerMinInterval = 100 * time.Millisecond
)

// AddressScopeMax sets the maximum scope an IP address can have. A scope
// is defined in rtnetlink(7) as the distance to the destination where a
// lower number signifies a wider scope with RT_SCOPE_UNIVERSE (0) being
// the widest. Definitions in Go are in unix package, e.g.
// unix.RT_SCOPE_UNIVERSE and so on.
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

type nodeAddressController struct {
	nodeAddressControllerParams

	tracker *statedb.DeleteTracker[*Device]
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
	g := n.Jobs.NewGroup(n.HealthScope)
	g.Add(job.OneShot("node-address-update", n.run))

	n.Lifecycle.Append(
		hive.Hook{
			OnStart: func(ctx hive.HookContext) error {
				txn := n.DB.WriteTxn(n.NodeAddresses, n.Devices /* for delete tracker */)
				defer txn.Abort()

				// Start tracking deletions of devices.
				var err error
				n.tracker, err = n.Devices.DeleteTracker(txn, "node-addresses")
				if err != nil {
					return fmt.Errorf("DeleteTracker: %w", err)
				}

				// Do an immediate update to populate the table before it is read from.
				devices, _ := n.Devices.All(txn)
				for dev, _, ok := devices.Next(); ok; dev, _, ok = devices.Next() {
					n.update(txn, nil, n.getAddressesFromDevice(dev), nil)
				}
				txn.Commit()

				// Start the job in the background to incremental refresh
				// the node addresses.
				return g.Start(ctx)
			},
			OnStop: g.Stop,
		})

}

func (n *nodeAddressController) run(ctx context.Context, reporter cell.HealthReporter) error {
	defer n.tracker.Close()

	limiter := rate.NewLimiter(nodeAddressControllerMinInterval, 1)
	revision := statedb.Revision(0)
	for {
		txn := n.DB.WriteTxn(n.NodeAddresses)
		process := func(dev *Device, deleted bool, rev statedb.Revision) error {
			addrIter, _ := n.NodeAddresses.Get(txn, NodeAddressDeviceNameIndex.Query(dev.Name))
			existing := statedb.CollectSet[NodeAddress](addrIter)
			var new sets.Set[NodeAddress]
			if !deleted {
				new = n.getAddressesFromDevice(dev)
			}
			n.update(txn, existing, new, reporter)
			return nil
		}
		var watch <-chan struct{}
		revision, watch, _ = n.tracker.Process(txn, revision, process)
		txn.Commit()

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

func (n *nodeAddressController) update(txn statedb.WriteTxn, existing, new sets.Set[NodeAddress], reporter cell.HealthReporter) {
	updated := false

	// Insert new addresses that did not exist.
	for addr := range new {
		if !existing.Has(addr) {
			updated = true
			n.NodeAddresses.Insert(txn, addr)
		}
	}

	// Remove addresses that were not part of the new set.
	for addr := range existing {
		if !new.Has(addr) {
			updated = true
			n.NodeAddresses.Delete(txn, addr)
		}
	}

	if updated {
		addrs := showAddresses(new)
		n.Log.WithField("node-addresses", addrs).Info("Node addresses updated")
		if reporter != nil {
			reporter.OK(addrs)
		}
	}
}

func (n *nodeAddressController) getAddressesFromDevice(dev *Device) (addrs sets.Set[NodeAddress]) {
	addrs = sets.New[NodeAddress]()

	if dev.Flags&net.FlagUp == 0 {
		return
	}

	if dev.Name == defaults.HostDevice {
		// If AddressScopeMax is a scope more broad (numerically less than) than SCOPE_LINK then
		// include all addresses at SCOPE_LINK which are assigned to the Cilium host device.
		if n.AddressScopeMax < unix.RT_SCOPE_LINK {
			for _, addr := range sortedAddresses(dev.Addrs) {
				if addr.Scope == unix.RT_SCOPE_LINK {
					addrs.Insert(NodeAddress{
						Addr:       addr.Addr,
						NodePort:   false,
						Primary:    false,
						DeviceName: dev.Name,
					})
				}

			}
		}
	} else {
		// Skip obviously uninteresting devices. We include the HostDevice as its IP addresses are
		// considered node addresses and added to e.g. ipcache as HOST_IDs.
		for _, prefix := range defaults.ExcludedDevicePrefixes {
			if strings.HasPrefix(dev.Name, prefix) {
				return
			}
		}
	}

	// ipv4Found and ipv6Found are set to true when the primary address is picked.
	// Used to implement 'NodePort' and 'Primary' flags.
	ipv4Found, ipv6Found := false, false

	for _, addr := range sortedAddresses(dev.Addrs) {
		// We keep the scope-based address filtering as was introduced
		// in 080857bdedca67d58ec39f8f96c5f38b22f6dc0b.
		if addr.Scope > uint8(n.AddressScopeMax) || addr.Addr.IsLoopback() {
			continue
		}

		// Figure out if the address is usable for NodePort.
		nodePort := false
		primary := false
		if dev.Selected && len(n.Config.NodePortAddresses) == 0 {
			// The user has not specified IP ranges to filter on IPs on which to serve NodePort.
			// Thus the default behavior is to use the primary IPv4 and IPv6 addresses of each
			// device.
			if addr.Addr.Is4() && !ipv4Found {
				ipv4Found = true
				nodePort = true
				primary = true
			}
			if addr.Addr.Is6() && !ipv6Found {
				ipv6Found = true
				nodePort = true
				primary = true
			}
		} else if ip.NetsContainsAny(n.Config.getNets(), []*net.IPNet{ip.IPToPrefix(addr.AsIP())}) {
			// User specified --nodeport-addresses and this address was within the range.
			nodePort = true
			if addr.Addr.Is4() && !ipv4Found {
				primary = true
				ipv4Found = true
			} else if addr.Addr.Is6() && !ipv6Found {
				primary = true
				ipv6Found = true
			}
		}

		addrs.Insert(NodeAddress{
			Addr:       addr.Addr,
			Primary:    primary,
			NodePort:   nodePort,
			DeviceName: dev.Name,
		})
	}
	return
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

// sortedAddresses returns a copy of the addresses, sorted by primary (e.g. !iIFA_F_SECONDARY) and then by
// address scope.
func sortedAddresses(addrs []DeviceAddress) []DeviceAddress {
	addrs = slices.Clone(addrs)

	sort.SliceStable(addrs, func(i, j int) bool {
		switch {
		case !addrs[i].Secondary && addrs[j].Secondary:
			return true
		case addrs[i].Secondary && !addrs[j].Secondary:
			return false
		default:
			return addrs[i].Scope < addrs[j].Scope
		}
	})
	return addrs
}
