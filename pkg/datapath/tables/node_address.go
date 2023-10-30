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

// NodeAddress is a host IP address on a Cilium node. It is a real address
// assigned to a specific network device. Derived from [*Device].
type NodeAddress struct {
	Addr netip.Addr

	// DeviceName is the name of the network device from which this address
	// is derived from.
	DeviceName string

	// NodePort is true if this address is to be used for NodePort.
	// If --nodeport-addresses is set, then all addresses on native
	// devices that are contained within the specified CIDRs are chosen.
	// If it is not set, then only the primary IPv4 and/or IPv6 address
	// of each native device is used.
	NodePort bool

	// Primary is true if this is the primary IPv4 or IPv6 address of this device.
	// This is mainly used to pick the address for BPF masquerading.
	Primary bool
}

func (n *NodeAddress) IP() net.IP {
	return n.Addr.AsSlice()
}

func (n *NodeAddress) String() string {
	return fmt.Sprintf("%s (%s)", n.Addr, n.DeviceName)
}

func (n *NodeAddress) TabHeader() string {
	return "Address\tDeviceName\tNodePort\tPrimary\n"
}

func (n *NodeAddress) TabRow() string {
	return fmt.Sprintf("%s\t%s\t%v\t%v\n", n.Addr, n.DeviceName, n.NodePort, n.Primary)
}

type NodeAddressConfig struct {
	// NodePortAddresses is a set of CIDRs that limit which IP addresses are used for NodePort.
	// By default empty, in which case the default semantics of using only the first IPv4
	// and/or IPv6 address per network device. The first address is determined by sorting
	// the addresses by secondary flag and scope, so that primary addresses with lowest
	// scope (e.g. global) are preferred.
	NodePortAddresses []*cidr.CIDR `mapstructure:"nodeport-addresses"`

	// AddressScopeMax controls the maximum address scope for addresses to be
	// considered host addresses. Affects which addresses are used for NodePort
	// and have HOST_ID entry in the ipcache.
	AddressScopeMax string `mapstructure:"local-max-addr-scope"`
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

		statedb.NewPrivateRWTableCell[NodeAddress](NodeAddressTableName, NodeAddressIndex),
		cell.Provide(
			newNodeAddressTable,
			newAddressScopeMax,
		),
		cell.Config(NodeAddressConfig{}),
	)

	// NodeAddressTestTableCell provides Table[NodeAddress] and RWTable[NodeAddress]
	// for use in tests of modules that depend on node addresses.
	NodeAddressTestTableCell = statedb.NewTableCell[NodeAddress](
		NodeAddressTableName,
		NodeAddressIndex,
	)
)

const (
	nodeAddressControllerMinInterval = 100 * time.Millisecond

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

	flags.String(addressScopeMaxFlag, fmt.Sprintf("%d", defaults.AddressScopeMax), "Maximum local address scope for node addresses")
	flags.MarkHidden(addressScopeMaxFlag)
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

	// current is the current set of node addresses inserted by this controller.
	current sets.Set[NodeAddress]

	tracker *statedb.DeleteTracker[*Device]
}

// newNodeAddressTable constructs the node address controller & registers its
// lifecycle hooks and then provides Table[NodeAddress] to the application.
// This enforces proper ordering, e.g. controller is started before anything
// that depends on Table[NodeAddress] and allows it to populate it before
// it is accessed.
func newNodeAddressTable(p nodeAddressControllerParams) (tbl statedb.Table[NodeAddress], err error) {
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

				var err error
				n.tracker, err = n.Devices.DeleteTracker(txn, "node-addresses")
				if err != nil {
					return fmt.Errorf("DeleteTracker: %w", err)
				}

				// Do an immediate update to populate the table
				// before it is read from.
				addrs := sets.New[NodeAddress]()
				devices, _ := n.Devices.All(txn)
				for dev, _, ok := devices.Next(); ok; dev, _, ok = devices.Next() {
					n.getAddressesFromDevice(dev, addrs)
				}
				n.update(txn, addrs, nil)
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
			new := n.current.Clone()

			// Remove the existing addresses for this device.
			for addr := range new {
				if addr.DeviceName == dev.Name {
					new.Delete(addr)
				}
			}
			if !deleted {
				// Add in the new addresses.
				n.getAddressesFromDevice(dev, new)
			}
			n.update(txn, new, reporter)
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

func (n *nodeAddressController) update(txn statedb.WriteTxn, new sets.Set[NodeAddress], reporter cell.HealthReporter) {
	updated := false

	// Insert new addresses that did not exist.
	for addr := range new.Difference(n.current) {
		updated = true
		n.NodeAddresses.Insert(txn, addr)
	}

	// Remove addresses that were not part of the new set.
	for addr := range n.current.Difference(new) {
		updated = true
		n.NodeAddresses.Delete(txn, addr)
	}

	if updated {
		addrs := showAddresses(new)
		n.Log.WithField("node-addresses", addrs).Info("Node addresses updated")
		if reporter != nil {
			reporter.OK(addrs)
		}
	}
}

func (n *nodeAddressController) getAddressesFromDevice(dev *Device, addrs sets.Set[NodeAddress]) {
	if dev.Flags&net.FlagUp == 0 {
		return
	}

	// Skip obviously uninteresting devices.
	// We include the HostDevice as its IP addresses are consider node addresses
	// and added to e.g. ipcache as HOST_IDs.
	if dev.Name != defaults.HostDevice {
		skip := false
		for _, prefix := range defaults.ExcludedDevicePrefixes {
			if strings.HasPrefix(dev.Name, prefix) {
				skip = true
				break
			}
		}
		if skip {
			return
		}
	}

	// ipv4 and ipv6 are set to true when the primary address is picked.
	// Used to implement 'NodePort' and 'Primary' flags.
	ipv4, ipv6 := false, false

	for _, addr := range sortAddresses(dev.Addrs) {
		// We keep the scope-based address filtering as was introduced
		// in 080857bdedca67d58ec39f8f96c5f38b22f6dc0b.
		if addr.Scope > uint8(n.AddressScopeMax) {
			// Addresses are sorted by scope, so can stop early.
			break
		}
		if addr.Addr.IsLoopback() {
			continue
		}

		// Figure out if the address is usable for NodePort.
		nodePort := false
		primary := false
		if dev.Selected && len(n.Config.NodePortAddresses) == 0 {
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
			// User specified --nodeport-addresses and this address was within the range.
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
