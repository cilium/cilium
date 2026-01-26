// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package neighbor

import (
	"context"
	"errors"
	"fmt"
	"iter"
	"net/netip"
	"slices"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"
	"github.com/cilium/statedb/reconciler"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"github.com/cilium/cilium/pkg/datapath/tables"
	"github.com/cilium/cilium/pkg/time"
)

type desiredNeighborCalculatorParams struct {
	cell.In

	DB                   *statedb.DB
	DesiredNeighborTable statedb.RWTable[*DesiredNeighbor]
	ForwardableIPTable   statedb.Table[*ForwardableIP]
	DeviceTable          statedb.Table[*tables.Device]
	RouteTable           statedb.Table[*tables.Route]
	FuncsGetter          *netlinkFuncsGetter
	Metrics              *neighborMetrics
	Config               *CommonConfig

	JobGroup job.Group
}

type desiredNeighborCalculator struct {
	desiredNeighborCalculatorParams

	desiredNeighborInitialized func(statedb.WriteTxn)
}

func newDesiredNeighborCalculator(p desiredNeighborCalculatorParams) (*desiredNeighborCalculator, error) {
	if !p.Config.Enabled {
		return nil, nil
	}

	tx := p.DB.WriteTxn(p.DesiredNeighborTable)
	initializer := p.DesiredNeighborTable.RegisterInitializer(
		tx,
		"desired-neighbor-calculator-initializer",
	)
	tx.Commit()

	dnc := &desiredNeighborCalculator{
		desiredNeighborCalculatorParams: p,
		desiredNeighborInitialized:      initializer,
	}

	dnc.JobGroup.Add(
		job.OneShot("desired-neighbor-calculator", dnc.Run),
	)

	return dnc, nil
}

func (c *desiredNeighborCalculator) Run(ctx context.Context, health cell.Health) error {
	// Latest revision of forwardable IPs processed
	fipRev := uint64(0)

	// We always start out needing a full sync
	needFullSyn := true

	// Resync every 5 minutes, this will account of any deletions of forwardable IPs as well
	// as catch any errors as result of an error in the partial sync.
	const resyncInterval = 5 * time.Minute
	resyncTimer := time.NewTimer(resyncInterval)

	for {
		rx := c.DB.ReadTxn()

		// Get inserted or updated forwardable IPs since the last revision processed
		var (
			fipSeq   iter.Seq2[*ForwardableIP, statedb.Revision]
			fipWatch <-chan struct{}
		)

		// If we need to do a full sync, we get all forwardable IPs
		// Otherwise, we get only the ones that have been updated since the last revision
		if needFullSyn {
			fipSeq, fipWatch = c.ForwardableIPTable.AllWatch(rx)
		} else {
			fipSeq, fipWatch = c.ForwardableIPTable.LowerBoundWatch(rx, statedb.ByRevision[*ForwardableIP](fipRev))
		}

		// Get all L2 devices
		l2Devs, l2DevWatch := l2Devices(c.DeviceTable, rx)

		// Get all permutations of forwardable IPs and L2 devices
		type fipWithDev struct {
			fip *ForwardableIP
			dev *tables.Device
		}
		permutations := iter.Seq[fipWithDev](func(yield func(fipWithDev) bool) {
			for fip, rev := range fipSeq {
				for _, dev := range l2Devs {
					// Store the last revision we processed
					fipRev = rev
					if !yield(fipWithDev{fip: fip, dev: dev}) {
						return
					}
				}
			}
		})

		// Add a watch for the routes table as it was at the start of the
		// transaction. We will be querying the FIB for next hops via netlink.
		// We do this since netlink applies the exact same logic as the datapath does when
		// determining the next hop for a given IP, which prevents subtle bugs.
		// However, the answer we get will become invalid if the routes change.
		// So we use the route table watch as signal for when to re-run this.
		_, routeWatch := c.RouteTable.AllWatch(rx)

		uniqueDesiredNeighbors := make(map[DesiredNeighborKey]struct{})

		var errs error
		// Find next hop routes for each forwardable IP
		for fipDev := range permutations {
			nextHop, err := c.getNextHopIP(fipDev.fip.IP, fipDev.dev.Index)
			if err != nil {
				if errors.Is(err, errNodeIPNotRoutable) {
					// If the node IP is not routable, we don't need to do anything
					continue
				}

				errs = errors.Join(errs, fmt.Errorf("failed to get next hop IP: %w", err))
				continue
			}

			uniqueDesiredNeighbors[DesiredNeighborKey{
				IP:      nextHop,
				IfIndex: fipDev.dev.Index,
			}] = struct{}{}
		}

		errs = errors.Join(errs, c.commitDesiredNeighbors(rx, needFullSyn, uniqueDesiredNeighbors))

		if errs != nil {
			health.Degraded("desired neighbor calculator errored", errs)
		}

		if needFullSyn {
			needFullSyn = false
			resyncTimer.Reset(resyncInterval)
		}

		select {
		case <-ctx.Done():
			// If we are shutting down, stop the loop
			return nil

		case <-fipWatch:
			// If there are updates to the forwardable IPs, do a partial sync
			continue

		case <-l2DevWatch:
			// If there are updates to the L2 devices, do a full sync
			needFullSyn = true

		case <-routeWatch:
			// If there are updates to the routes, do a full sync
			needFullSyn = true

		case <-resyncTimer.C:
			// If the resync timer fires, do a full sync
			needFullSyn = true
		}
	}
}

func (c *desiredNeighborCalculator) commitDesiredNeighbors(
	rx statedb.ReadTxn,
	needFullSyn bool,
	uniqueDesiredNeighbors map[DesiredNeighborKey]struct{},
) error {
	var errs error

	tx := c.DB.WriteTxn(c.DesiredNeighborTable)
	defer tx.Abort()

	// If we are doing a full sync, first delete all entries that should not be
	// present anymore.
	if needFullSyn {
		for dn := range c.DesiredNeighborTable.All(rx) {
			// If the desired neighbor is not in the set of unique desired neighbors,
			// delete it.
			if _, ok := uniqueDesiredNeighbors[dn.DesiredNeighborKey]; !ok {
				if _, _, err := c.DesiredNeighborTable.Delete(tx, dn); err != nil {
					errs = errors.Join(errs, fmt.Errorf("failed to delete desired neighbor: %w", err))
				}
			}
		}
	}

	for dnKey := range uniqueDesiredNeighbors {
		// Insert the desired neighbor into the table if it doesn't exist.
		// Do not modify the old entry if it exists.
		if _, _, err := c.DesiredNeighborTable.Modify(tx, &DesiredNeighbor{
			DesiredNeighborKey: dnKey,
			Status:             reconciler.StatusPending(),
		}, func(old *DesiredNeighbor, new *DesiredNeighbor) *DesiredNeighbor {
			// New object, but no modifications
			new.DesiredNeighborKey = old.DesiredNeighborKey
			new.Status = old.Status
			return new
		}); err != nil {
			errs = errors.Join(errs, fmt.Errorf("failed to insert desired neighbor: %w", err))
		}
	}

	// If the forwardable IP table is initialized in the read transaction,
	// then mark the desired neighbor table as initialized as well.
	if init, _ := c.ForwardableIPTable.Initialized(rx); init {
		c.desiredNeighborInitialized(tx)
	}

	tx.Commit()

	return errs
}

var errNodeIPNotRoutable = errors.New("remote node IP is non-routable")

func (c *desiredNeighborCalculator) getNextHopIP(fip netip.Addr, ifindex int) (nextHopIP netip.Addr, err error) {
	c.Metrics.NexthopLookupCount.Inc()

	// Figure out whether nodeIP is directly reachable (i.e. in the same L2)
	routes, err := c.FuncsGetter.Get().RouteGetWithOptions(fip.AsSlice(), &netlink.RouteGetOptions{
		OifIndex: ifindex,
		FIBMatch: true,
	})
	if err != nil && !errors.Is(err, unix.EHOSTUNREACH) && !errors.Is(err, unix.ENETUNREACH) {
		return netip.Addr{}, fmt.Errorf("failed to retrieve route for remote node IP: %w", err)
	}
	if len(routes) == 0 {
		return netip.Addr{}, errNodeIPNotRoutable
	}

	nextHopIP = fip
	for _, route := range routes {
		if route.Gw != nil {
			// nodeIP is in a different L2 subnet, so it must be reachable through
			// a gateway. Perform neighbor discovery to the gw IP addr instead of
			// nodeIP. NOTE: We currently don't handle multipath, so only one gw
			// can be used.

			if route.Gw.To4() == nil {
				nextHopIP, _ = netip.AddrFromSlice(route.Gw.To16())
			} else {
				nextHopIP, _ = netip.AddrFromSlice(route.Gw.To4())
			}
			break
		}

		// Select a gw for the specified link if there are multi paths to the nodeIP
		// For example, the nextHop to the nodeIP 9.9.9.9 from eth0 is 10.0.1.2,
		// from eth1 is 10.0.2.2 as shown bellow.
		//
		// 9.9.9.9 proto bird metric 32
		//        nexthop via 10.0.1.2 dev eth0 weight 1
		//        nexthop via 10.0.2.2 dev eth1 weight 1
		//
		// NOTE: We currently don't handle multiple next hops, so only one next hop
		// per device can be used.
		if route.MultiPath != nil {
			for _, mp := range route.MultiPath {
				if mp.LinkIndex == ifindex {
					if mp.Gw.To4() == nil {
						nextHopIP, _ = netip.AddrFromSlice(mp.Gw.To16())
					} else {
						nextHopIP, _ = netip.AddrFromSlice(mp.Gw.To4())
					}
					break
				}
			}
		}
	}

	return nextHopIP, nil
}

func l2Devices(tbl statedb.Table[*tables.Device], rx statedb.ReadTxn) ([]*tables.Device, <-chan struct{}) {
	devIter, watch := tbl.ListWatch(rx, tables.DeviceSelectedIndex.Query(true))

	return slices.Collect(func(yield func(*tables.Device) bool) {
		for dev := range devIter {
			if len(dev.HardwareAddr) != 0 {
				if !yield(dev) {
					return
				}
			}
		}
	}), watch
}
