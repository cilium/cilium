// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package writer

import (
	"context"
	"log/slog"

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

type nodePortAddressReconcilerParams struct {
	cell.In

	Config   loadbalancer.Config
	JobGroup job.Group
	Log      *slog.Logger

	DB            *statedb.DB
	NodeAddresses statedb.Table[tables.NodeAddress]
	Frontends     statedb.Table[*loadbalancer.Frontend]
}

func registerNodePortAddressReconciler(p nodePortAddressReconcilerParams) {
	if !p.Config.EnableExperimentalLB {
		return
	}

	r := nodePortAddrReconciler{
		log:       p.Log,
		db:        p.DB,
		nodeAddrs: p.NodeAddresses,
		frontends: p.Frontends.(statedb.RWTable[*loadbalancer.Frontend]),
	}

	p.JobGroup.Add(job.OneShot("node-addr-reconciler", r.nodePortAddressReconcilerLoop))
}

type nodePortAddrReconciler struct {
	log       *slog.Logger
	db        *statedb.DB
	nodeAddrs statedb.Table[tables.NodeAddress]
	frontends statedb.RWTable[*loadbalancer.Frontend]
}

func (r *nodePortAddrReconciler) nodePortAddressReconcilerLoop(ctx context.Context, health cell.Health) error {
	// Limit the rate of processing to avoid unnecessary churn, but keep it fast enough for humans.
	limiter := rate.NewLimiter(time.Second, 1)
	defer limiter.Stop()

	for {
		wtxn := r.db.WriteTxn(r.frontends)
		_, watch := r.nodeAddrs.ListWatch(wtxn, tables.NodeAddressNodePortIndex.Query(true))

		// The node port addresses have changed, set all NodePort/HostPort frontends as pending to reconcile
		// the new addresses.
		for fe := range r.frontends.All(wtxn) {
			if fe.Type != loadbalancer.SVCTypeNodePort &&
				!(fe.Type == loadbalancer.SVCTypeHostPort && fe.Address.AddrCluster.IsUnspecified()) {
				continue
			}

			fe = fe.Clone()
			// Set status to Pending, so that BPFOps reconciler gets invoked to update Frontend(s)' addrs accordingly
			fe.Status = reconciler.StatusPending()
			_, _, err := r.frontends.Insert(wtxn, fe)
			if err != nil {
				// Should not happen, but let's log it anyway
				r.log.Warn("Could not set frontend status to pending",
					logfields.Frontend, fe,
					logfields.Error, err,
				)
			}
		}

		wtxn.Commit()

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
