// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package l2responder

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"runtime/pprof"

	"github.com/cilium/cilium/pkg/datapath/garp"
	"github.com/cilium/cilium/pkg/datapath/tables"
	"github.com/cilium/cilium/pkg/ebpf"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/hive/job"
	"github.com/cilium/cilium/pkg/maps/l2respondermap"
	"github.com/cilium/cilium/pkg/statedb"
	"github.com/cilium/cilium/pkg/time"
	"github.com/cilium/cilium/pkg/types"

	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
)

// Cell provides the L2 Responder Reconciler. This component takes the desired state, calculated by
// the L2 announcer component from the StateDB table and reconciles it with the L2 responder map.
// The L2 Responder Reconciler watches for incremental changes in the table and applies these
// incremental changes immediately and it periodically perform full reconciliation as redundancy.
var Cell = cell.Module(
	"l2-responder",
	"L2 Responder Reconciler",

	// Provide and register the Table[*L2AnnounceEntry] containing the
	// desired state.
	cell.Provide(
		tables.NewL2AnnounceTable,
		statedb.RWTable[*tables.L2AnnounceEntry].ToTable,
	),
	cell.Invoke(statedb.RegisterTable[*tables.L2AnnounceEntry]),

	cell.Invoke(NewL2ResponderReconciler),
	cell.Provide(newNeighborNetlink),
)

type params struct {
	cell.In

	Lifecycle           hive.Lifecycle
	Logger              logrus.FieldLogger
	L2AnnouncementTable statedb.RWTable[*tables.L2AnnounceEntry]
	StateDB             *statedb.DB
	L2ResponderMap      l2respondermap.Map
	NetLink             linkByNamer
	JobRegistry         job.Registry
	Scope               cell.Scope
}

type linkByNamer interface {
	LinkByName(name string) (netlink.Link, error)
}

func newNeighborNetlink() linkByNamer {
	return &netlink.Handle{}
}

type l2ResponderReconciler struct {
	params params
}

func NewL2ResponderReconciler(params params) *l2ResponderReconciler {
	reconciler := l2ResponderReconciler{
		params: params,
	}

	group := params.JobRegistry.NewGroup(
		params.Scope,
		job.WithLogger(params.Logger),
		job.WithPprofLabels(pprof.Labels("cell", "l2-responder-reconciler")),
	)
	params.Lifecycle.Append(group)
	group.Add(job.OneShot("l2-responder-reconciler", reconciler.run))

	return &reconciler
}

func (p *l2ResponderReconciler) run(ctx context.Context, health cell.HealthReporter) error {
	log := p.params.Logger

	// This timer triggers full reconciliation once in a while, in case partial reconciliation
	// got out of sync or the map was changed underneath us.
	ticker := time.NewTicker(5 * time.Minute)

	tbl := p.params.L2AnnouncementTable
	txn := p.params.StateDB.WriteTxn(tbl)
	tracker, err := tbl.DeleteTracker(txn, "l2-responder-reconciler")
	if err != nil {
		txn.Abort()
		return fmt.Errorf("delete tracker: %w", err)
	}
	txn.Commit()

	defer tracker.Close()

	// At startup, do an initial full reconciliation
	maxRev, err := p.fullReconciliation()
	if err != nil {
		log.WithError(err).Error("Error(s) while reconciling l2 responder map")
	}

	for ctx.Err() == nil {
		maxRev = p.cycle(ctx, tracker, maxRev, ticker.C)
	}

	return nil
}

func (p *l2ResponderReconciler) cycle(
	ctx context.Context,
	tracker *statedb.DeleteTracker[*tables.L2AnnounceEntry],
	maxRevIn statedb.Revision,
	fullReconciliation <-chan time.Time,
) (maxRev statedb.Revision) {
	arMap := p.params.L2ResponderMap
	rtx := p.params.StateDB.ReadTxn()
	log := p.params.Logger

	lr := cachingLinkResolver{nl: p.params.NetLink}

	// Partial reconciliation
	maxRev, invalid, err := tracker.Process(rtx, maxRevIn, func(e *tables.L2AnnounceEntry, deleted bool, rev uint64) error {
		// Ignore IPv6 addresses, L2 is IPv4 only
		if e.IP.Is6() {
			return nil
		}

		idx, err := lr.LinkIndex(e.NetworkInterface)
		if err != nil {
			return fmt.Errorf("link index: %w", err)
		}

		if deleted {
			err = arMap.Delete(e.IP, uint32(idx))
			if err != nil {
				return fmt.Errorf("delete %s@%d: %w", e.IP, idx, err)
			}

			return nil
		}

		err = garpOnNewEntry(arMap, e.IP, idx)
		if err != nil {
			return err
		}

		err = arMap.Create(e.IP, uint32(idx))
		if err != nil {
			return fmt.Errorf("create %s@%d: %w", e.IP, idx, err)
		}

		return nil
	})
	if err != nil {
		log.WithError(err).Error("error during partial reconciliation")
	}

	select {
	case <-ctx.Done():
		// Shutdown
		return 0

	case <-invalid:
		// There are pending changes in the table, return from the cycle
		return maxRev

	case <-fullReconciliation:
		// Full reconciliation timer fired, perform full reconciliation

		// The existing `iter` is the result of a `All` query, so this will return all
		// entries in the table for full reconciliation.
		maxRev, err = p.fullReconciliation()
		if err != nil {
			log.WithError(err).Error("Error(s) while full reconciling l2 responder map")
		}

		return maxRev
	}
}

func (p *l2ResponderReconciler) fullReconciliation() (maxRev uint64, err error) {
	var errs error

	log := p.params.Logger
	tbl := p.params.L2AnnouncementTable
	db := p.params.StateDB
	arMap := p.params.L2ResponderMap
	lr := cachingLinkResolver{nl: p.params.NetLink}

	log.Debug("l2 announcer table full reconciliation")

	// Get all desired entries in the table
	rtx := db.ReadTxn()
	iter, _ := tbl.All(rtx)

	// Prepare index for desired entries based on map key
	type desiredEntry struct {
		satisfied bool
		entry     *tables.L2AnnounceEntry
	}
	desiredMap := make(map[l2respondermap.L2ResponderKey]desiredEntry)

	statedb.ProcessEach(iter, func(e *tables.L2AnnounceEntry, _ uint64) error {
		// Ignore IPv6 addresses, L2 is IPv4 only
		if e.IP.Is6() {
			return nil
		}

		idx, err := lr.LinkIndex(e.NetworkInterface)
		if err != nil {
			errs = errors.Join(errs, err)
			return nil
		}

		desiredMap[l2respondermap.L2ResponderKey{
			IP:      types.IPv4(e.IP.As4()),
			IfIndex: uint32(idx),
		}] = desiredEntry{
			entry: e,
		}

		return nil
	})

	// Loop over all map values, use the desired entries index to see which we want to delete.
	var toDelete []*l2respondermap.L2ResponderKey
	arMap.IterateWithCallback(func(key *l2respondermap.L2ResponderKey, _ *l2respondermap.L2ResponderStats) {
		e, found := desiredMap[*key]
		if !found {
			toDelete = append(toDelete, key)
			return
		}
		e.satisfied = true
	})

	// Delete all unwanted map values
	for _, del := range toDelete {
		if err := arMap.Delete(netip.AddrFrom4(del.IP), del.IfIndex); err != nil {
			errs = errors.Join(errs, fmt.Errorf("delete %s@%d: %w", del.IP, del.IfIndex, err))
		}
	}

	// Add map values that do not yet exist
	for key, entry := range desiredMap {
		if entry.satisfied {
			continue
		}

		err = garpOnNewEntry(arMap, netip.AddrFrom4(key.IP), int(key.IfIndex))
		if err != nil {
			errs = errors.Join(errs, err)
		}

		if err := arMap.Create(netip.AddrFrom4(key.IP), key.IfIndex); err != nil {
			errs = errors.Join(errs, fmt.Errorf("create %s@%d: %w", key.IP, key.IfIndex, err))
		}
	}

	return maxRev, errs
}

// If the given IP and network interface index does not yet exist in the l2 responder map,
// a failover might have taken place. Therefor we should send out a gARP reply to let
// the local network know the IP has moved to minimize downtime due to ARP caching.
func garpOnNewEntry(arMap l2respondermap.Map, ip netip.Addr, ifIndex int) error {
	_, err := arMap.Lookup(ip, uint32(ifIndex))
	if !errors.Is(err, ebpf.ErrKeyNotExist) {
		return nil
	}

	err = garp.SendOnInterfaceIdx(ifIndex, ip)
	if err != nil {
		return fmt.Errorf("garp %s@%d: %w", ip, ifIndex, err)
	}

	return nil
}

type cachingLinkResolver struct {
	nl    linkByNamer
	cache map[string]int
}

// LinkIndex returns the link index for a given netdev name, from its cache or netlink
func (clr *cachingLinkResolver) LinkIndex(name string) (int, error) {
	if clr.cache == nil {
		clr.cache = make(map[string]int)
	}

	idx, found := clr.cache[name]
	if found {
		return idx, nil
	}

	link, err := clr.nl.LinkByName(name)
	if err != nil {
		return 0, err
	}

	idx = link.Attrs().Index
	clr.cache[name] = idx

	return idx, nil
}
