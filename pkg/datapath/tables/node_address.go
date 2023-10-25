// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package tables

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/spf13/pflag"
	"k8s.io/apimachinery/pkg/util/sets"

	"github.com/cilium/cilium/pkg/cidr"
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

	Primary    bool // True if this is the primary address of this device.
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
		),
		cell.Config(NodeAddressConfig{}),
	)
)

type NodeAddressConfig struct {
	NodeAddresses []*cidr.CIDR `mapstructure:"node-addresses"`
}

func (cfg NodeAddressConfig) getNets() []*net.IPNet {
	nets := make([]*net.IPNet, len(cfg.NodeAddresses))
	for i, cidr := range cfg.NodeAddresses {
		nets[i] = cidr.IPNet
	}
	return nets
}

func (NodeAddressConfig) Flags(flags *pflag.FlagSet) {
	flags.StringSlice(
		"node-addresses",
		nil,
		"A whitelist of CIDRs to limit which IPs are considered node addresses. If not set, primary IP address of each native device is used.")
}

type nodeAddressSource struct {
	cell.In

	HealthScope   cell.Scope
	Log           logrus.FieldLogger
	Config        NodeAddressConfig
	Lifecycle     hive.Lifecycle
	Jobs          job.Registry
	DB            *statedb.DB
	Devices       statedb.Table[*Device]
	NodeAddresses statedb.RWTable[NodeAddress]
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

	devs, watch := SelectedDevices(n.Devices, txn)

	old := n.getCurrentAddresses(txn)
	new := n.getAddressesFromDevices(devs)
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

func (n *nodeAddressSource) getAddressesFromDevices(devs []*Device) (addrs sets.Set[NodeAddress]) {
	addrs = sets.New[NodeAddress]()
	for _, dev := range devs {
		first := true
		for _, addr := range dev.Addrs {
			if len(n.Config.NodeAddresses) == 0 {
				addrs.Insert(NodeAddress{Addr: addr.Addr, Primary: first, DeviceName: dev.Name})

				// The default behavior when --nodeport-addresses is not set is
				// to only use the primary IP of each device, so stop here.
				break
			} else if ip.NetsContainsAny(n.Config.getNets(), []*net.IPNet{ip.IPToPrefix(addr.AsIP())}) {
				addrs.Insert(NodeAddress{Addr: addr.Addr, Primary: first, DeviceName: dev.Name})
			}

			first = false
		}
	}
	return
}

// showAddresses formats a Set[NodeAddress] as "1.2.3.4 (eth0), fe80::1 (eth1)"
func showAddresses(addrs sets.Set[NodeAddress]) string {
	ss := make([]string, 0, len(addrs))
	for addr := range addrs {
		ss = append(ss, addr.String())
	}
	return strings.Join(ss, ", ")
}
