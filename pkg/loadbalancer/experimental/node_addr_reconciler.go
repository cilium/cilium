// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package experimental

import (
	"context"
	"log/slog"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"
	"github.com/cilium/statedb/reconciler"

	"github.com/cilium/cilium/pkg/datapath/tables"
	"github.com/cilium/cilium/pkg/loadbalancer"
)

type nodePortAddressReconcilerParams struct {
	cell.In

	Config   Config
	JobGroup job.Group
	Log      *slog.Logger

	DB            *statedb.DB
	NodeAddresses statedb.Table[tables.NodeAddress]
	Frontends     statedb.Table[*Frontend]
}

func registerNodePortAddressReconciler(p nodePortAddressReconcilerParams) {
	if !p.Config.EnableExperimentalLB {
		return
	}

	r := nodePortAddrReconciler{
		log:       p.Log,
		db:        p.DB,
		nodeAddrs: p.NodeAddresses,
		frontends: p.Frontends.(statedb.RWTable[*Frontend]),
	}

	p.JobGroup.Add(job.OneShot("node-addr-reconciler", r.nodePortAddressReconcilerLoop))
}

type nodePortAddrReconciler struct {
	log       *slog.Logger
	db        *statedb.DB
	nodeAddrs statedb.Table[tables.NodeAddress]
	frontends statedb.RWTable[*Frontend]
}

func (r *nodePortAddrReconciler) nodePortAddressReconcilerLoop(ctx context.Context, health cell.Health) error {
	for {
		wtxn := r.db.WriteTxn(r.frontends)

		_, watch := r.nodeAddrs.ListWatch(wtxn, tables.NodeAddressNodePortIndex.Query(true))

		for fe := range r.frontends.All(wtxn) {
			if fe.Type != loadbalancer.SVCTypeNodePort &&
				!(fe.Type == loadbalancer.SVCTypeHostPort && fe.Address.AddrCluster.IsUnspecified()) {
				continue
			}

			fe = fe.Clone()
			// Set status to Pending, so that BPFOps reconciler gets invoked to update Frontend(s)' addrs accordingly
			fe.setStatus(reconciler.StatusPending())
			_, _, err := r.frontends.Insert(wtxn, fe)
			if err != nil {
				// Should not happen, but let's log it anyway
				r.log.Warn("Could not set frontend status to pending", "frontend", fe, "error", err)
			}
		}

		wtxn.Commit()

		select {
		case <-ctx.Done():
			return nil
		case <-watch:
		}
	}
}
