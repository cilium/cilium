// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package l2responder

import (
	"context"
	"errors"
	"fmt"
	"runtime/pprof"
	"time"

	"github.com/cilium/cilium/pkg/datapath/tables"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/hive/job"
	"github.com/cilium/cilium/pkg/maps/l2respondermap"
	"github.com/cilium/cilium/pkg/statedb"
	"github.com/cilium/cilium/pkg/types"
	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
)

var Cell = cell.Module("l2-responder", "L2 Responder Reconciler",
	cell.Invoke(NewL2ResponderReconciler),
	cell.Provide(newNeighborNetlink),
)

type params struct {
	cell.In

	Lifecycle           hive.Lifecycle
	Logger              logrus.FieldLogger
	L2AnnouncementTable statedb.Table[*tables.L2AnnounceEntry]
	StateDB             statedb.DB
	L2ResponderMap      l2respondermap.Map
	NetLink             linkByNamer
	JobRegistry         job.Registry
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
		job.WithLogger(params.Logger),
		job.WithPprofLabels(pprof.Labels("cell", "l2-responder-reconciler")),
	)
	params.Lifecycle.Append(group)
	group.Add(job.OneShot("l2-responder-reconciler", reconciler.run))

	return &reconciler
}

func (p *l2ResponderReconciler) run(ctx context.Context) error {
	log := p.params.Logger

	// This timer triggers full reconciliation once in a while, in case partial reconciliation
	// got out of sync or the map was changed underneath us.
	ticker := time.NewTicker(5 * time.Minute)

	// At startup, do an initial full reconciliation
	maxRev, err := p.fullReconciliation()
	if err != nil {
		log.WithError(err).Error("Error(s) while reconciling l2 responder map")
	}

	for ctx.Err() == nil {
		maxRev = p.cycle(ctx, maxRev, ticker.C)
	}

	return nil
}

func (p *l2ResponderReconciler) cycle(
	ctx context.Context,
	maxRevIn uint64,
	fullReconciliation <-chan time.Time,
) (maxRev uint64) {
	tbl := p.params.L2AnnouncementTable
	db := p.params.StateDB
	log := p.params.Logger

	// Get an `iter` which invalidates on any changes.
	r := tbl.Reader(db.ReadTxn())
	iter, err := r.Get(statedb.All)
	if err != nil {
		log.WithError(err).Error("Error getting all desired proxy table entries")
	}

	select {
	case <-ctx.Done():
		return 0

	case <-iter.Invalidated():
		maxRev, err = p.partialReconciliation(maxRevIn)
		if err != nil {
			log.WithError(err).Error("Error(s) while partial reconciling l2 responder map")
		}

		return maxRev

	case <-fullReconciliation:

		// The existing `iter` is the result of a `All` query, so this will return all
		// entries in the table for full reconciliation.
		maxRev, err = p.fullReconciliation()
		if err != nil {
			log.WithError(err).Error("Error(s) while full reconciling l2 responder map")
		}

		return maxRev
	}
}

func (p *l2ResponderReconciler) partialReconciliation(maxRevIn uint64) (maxRev uint64, err error) {
	var errs error

	maxRev = maxRevIn

	arMap := p.params.L2ResponderMap
	tbl := p.params.L2AnnouncementTable
	db := p.params.StateDB
	log := p.params.Logger
	lr := cachingLinkResolver{nl: p.params.NetLink}

	log.Info("l2 announcer table invalidated, performing partial reconciliation")

	// Get all changes since the revision we processes
	r := tbl.Reader(db.ReadTxn())
	iter, err := r.LowerBound(statedb.ByRevision(maxRevIn))
	if err != nil {
		log.WithError(err).Error("Error getting last changes")
	}

	// A list of desired entries which have been soft deleted
	var toDelete []*tables.L2AnnounceEntry

	statedb.ProcessEach(iter, func(e *tables.L2AnnounceEntry) error {
		if e.Revision > maxRev {
			maxRev = e.Revision
		}

		// Ignore IPv6 addresses, L2 is IPv4 only
		if e.IP.To4() == nil {
			return nil
		}

		idx, err := lr.LinkIndex(e.NetworkInterface)
		if err != nil {
			errs = errors.Join(errs, fmt.Errorf("link index: %w", err))
			return nil
		}

		if e.Deleted {
			toDelete = append(toDelete, e)
			err = arMap.Delete(e.IP, uint32(idx))
			if err != nil {
				errs = errors.Join(errs, fmt.Errorf("delete %s@%d: %w", e.IP, idx, err))
			}
			return nil
		}

		err = arMap.Create(e.IP, uint32(idx))
		if err != nil {
			errs = errors.Join(errs, fmt.Errorf("create %s@%d: %w", e.IP, idx, err))
		}

		return nil
	})

	// Hard delete, soft deleted entries
	if len(toDelete) > 0 {
		txn := db.WriteTxn()
		w := tbl.Writer(txn)
		for _, e := range toDelete {
			if err = w.Delete(e); err != nil {
				errs = errors.Join(errs, fmt.Errorf("delete from table: %w", err))
			}
		}
		if err = txn.Commit(); err != nil {
			errs = errors.Join(errs, fmt.Errorf("commit deletion to table: %w", err))
		}
	}

	return maxRev, errs
}

func (p *l2ResponderReconciler) fullReconciliation() (maxRev uint64, err error) {
	var errs error

	log := p.params.Logger
	tbl := p.params.L2AnnouncementTable
	db := p.params.StateDB
	arMap := p.params.L2ResponderMap
	lr := cachingLinkResolver{nl: p.params.NetLink}

	log.Info("l2 announcer table full reconciliation")

	// Get all desired entries in the table
	r := tbl.Reader(db.ReadTxn())
	iter, err := r.Get(statedb.All)
	if err != nil {
		log.WithError(err).Error("Error getting all desired proxy table entries")
	}

	// Prepare index for desired entries based on map key
	type desiredEntry struct {
		satisfied bool
		entry     *tables.L2AnnounceEntry
	}
	desiredMap := make(map[l2respondermap.L2ResponderKey]desiredEntry)

	// A list of desired entries which have been soft deleted
	var tblEntriesToDelete []*tables.L2AnnounceEntry

	statedb.ProcessEach(iter, func(e *tables.L2AnnounceEntry) error {
		// Track the max revision number, used for partial reconciliation afterwards
		if e.Revision > maxRev {
			maxRev = e.Revision
		}

		if e.Deleted {
			tblEntriesToDelete = append(tblEntriesToDelete, e)
			return nil
		}

		// Ignore IPv6 addresses, L2 is IPv4 only
		if e.IP.To4() == nil {
			return nil
		}

		idx, err := lr.LinkIndex(e.NetworkInterface)
		if err != nil {
			errs = errors.Join(errs, err)
			return nil
		}

		desiredMap[l2respondermap.L2ResponderKey{
			IP:      types.IPv4(e.IP.To4()),
			IfIndex: uint32(idx),
		}] = desiredEntry{
			entry: e,
		}

		return nil
	})

	// Hard delete, soft deleted entries
	if len(tblEntriesToDelete) > 0 {
		txn := db.WriteTxn()
		w := tbl.Writer(txn)
		for _, e := range tblEntriesToDelete {
			if err = w.Delete(e); err != nil {
				errs = errors.Join(errs, fmt.Errorf("delete from table: %w", err))
			}
		}
		if err = txn.Commit(); err != nil {
			errs = errors.Join(errs, fmt.Errorf("commit deletion to table: %w", err))
		}
	}

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
		if err := arMap.Delete(del.IP[:], del.IfIndex); err != nil {
			errs = errors.Join(errs, fmt.Errorf("delete %s@%d: %w", del.IP, del.IfIndex, err))
		}
	}

	// Add map values that do not yet exist
	for key, entry := range desiredMap {
		if entry.satisfied {
			continue
		}

		if err := arMap.Create(key.IP[:], key.IfIndex); err != nil {
			errs = errors.Join(errs, fmt.Errorf("create %s@%d: %w", key.IP, key.IfIndex, err))
		}
	}

	return maxRev, errs
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
