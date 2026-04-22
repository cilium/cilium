// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package writer

import (
	"context"
	"log/slog"
	"net/netip"
	"slices"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"
	"github.com/cilium/statedb/reconciler"

	"github.com/cilium/cilium/pkg/datapath/tables"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/rate"
	"github.com/cilium/cilium/pkg/time"
)

type wildcardAddressReconcilerParams struct {
	cell.In

	Lifecycle cell.Lifecycle
	JobGroup  job.Group
	Log       *slog.Logger

	DB            *statedb.DB
	NodeAddresses statedb.Table[tables.NodeAddress]
	Frontends     statedb.Table[*loadbalancer.Frontend]
}

func registerWildcardAddressReconciler(p wildcardAddressReconcilerParams) {
	r := wildcardAddressReconciler{
		log:       p.Log,
		db:        p.DB,
		nodeAddrs: p.NodeAddresses,
		frontends: p.Frontends.(statedb.RWTable[*loadbalancer.Frontend]),
	}

	// Grab the initial read transaction synchronously from a start hook so the
	// initial node-address snapshot is taken after the table has been populated.
	p.Lifecycle.Append(cell.Hook{
		OnStart: func(hc cell.HookContext) error {
			r.initTxn = p.DB.ReadTxn()
			return nil
		},
	})

	p.JobGroup.Add(job.OneShot("wildcard-addr-reconciler", r.wildcardAddressReconcilerLoop))
}

type wildcardAddressReconciler struct {
	log       *slog.Logger
	db        *statedb.DB
	nodeAddrs statedb.Table[tables.NodeAddress]
	frontends statedb.RWTable[*loadbalancer.Frontend]
	initTxn   statedb.ReadTxn
}

func (r *wildcardAddressReconciler) getAddrs(txn statedb.ReadTxn) ([]netip.Addr, <-chan struct{}) {
	iter, watch := r.nodeAddrs.AllWatch(txn)
	addrs := statedb.Collect(statedb.Map(iter, func(addr tables.NodeAddress) netip.Addr {
		return addr.Addr
	}))
	slices.SortFunc(addrs, func(a, b netip.Addr) int {
		return a.Compare(b)
	})
	return slices.Compact(addrs), watch
}

func (r *wildcardAddressReconciler) wildcardAddressReconcilerLoop(ctx context.Context, health cell.Health) error {
	// Limit the rate of processing to avoid unnecessary churn, but keep it fast enough for humans.
	limiter := rate.NewLimiter(time.Second, 1)
	defer limiter.Stop()

	prevAddrs, watch := r.getAddrs(r.initTxn)
	r.initTxn = nil

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-watch:
		}

		wtxn := r.db.WriteTxn(r.frontends)
		var newAddrs []netip.Addr
		newAddrs, watch = r.getAddrs(wtxn)

		if !slices.Equal(prevAddrs, newAddrs) {
			// At the time of writing there's no index on the Frontends table that would let
			// us gracefully filter frontends by node-addresses. So, we query all frontends and
			// check if an FE is a wildcard candidate to reduce noise. It's not perfect but can
			// be improved later if it becomes a bottleneck.
			for fe := range r.frontends.All(wtxn) {
				if !loadbalancer.IsWildcardCandidate(fe) {
					continue
				}

				fe = fe.Clone()
				fe.Status = reconciler.StatusPending()
				_, _, err := r.frontends.Insert(wtxn, fe)
				if err != nil {
					r.log.Warn("Could not set wildcard frontend status to pending",
						logfields.Frontend, fe,
						logfields.Error, err,
					)
				}
			}
			prevAddrs = newAddrs
			wtxn.Commit()
		} else {
			wtxn.Abort()
		}
		if err := limiter.Wait(ctx); err != nil {
			return err
		}
	}
}
