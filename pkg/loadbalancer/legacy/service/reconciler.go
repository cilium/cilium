// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package service

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"
	"k8s.io/apimachinery/pkg/util/sets"

	"github.com/cilium/cilium/pkg/backoff"
	"github.com/cilium/cilium/pkg/datapath/tables"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/time"
)

// registerServiceReconciler registers a background job to synchronize NodePort frontends
// with the new set of node addresses assigned for NodePort use.
func registerServiceReconciler(p serviceReconcilerParams) {
	sr := serviceReconciler(p)
	g := p.Jobs.NewGroup(p.Health, p.Lifecycle)
	g.Add(job.OneShot("service-reconciler", sr.reconcileLoop))
}

type syncNodePort interface {
	SyncNodePortFrontends(sets.Set[netip.Addr]) error
}

type serviceReconcilerParams struct {
	cell.In

	Logger         *slog.Logger
	Lifecycle      cell.Lifecycle
	Jobs           job.Registry
	Health         cell.Health
	DB             *statedb.DB
	NodeAddresses  statedb.Table[tables.NodeAddress]
	ServiceManager syncNodePort
}

type serviceReconciler serviceReconcilerParams

func (sr serviceReconciler) reconcileLoop(ctx context.Context, health cell.Health) error {
	var (
		retry        <-chan time.Time
		retryAttempt int
		addrs        sets.Set[netip.Addr]
	)

	// Use exponential backoff for retries. Keep small minimum time for fast tests,
	// but backoff with aggressive factor.
	backoff := backoff.Exponential{
		Logger: sr.Logger,
		Min:    10 * time.Millisecond,
		Max:    30 * time.Second,
		Factor: 8,
	}

	// Perform a sync periodically. This resolves the rare races where k8s.ParseService uses old
	// set of frontend addresses. This will eventually be fixed by moving the NodePort frontend
	// expansion further down the stack, ideally to datapath.
	const periodicSyncInterval = 15 * time.Minute
	periodicSyncTicker := time.NewTicker(periodicSyncInterval)
	defer periodicSyncTicker.Stop()

	for {
		iter, watch := sr.NodeAddresses.AllWatch(sr.DB.ReadTxn())

		// Collect all NodePort addresses
		newAddrs := sets.New(statedb.Collect(
			statedb.Map(
				statedb.Filter(
					iter,
					func(addr tables.NodeAddress) bool { return addr.NodePort },
				),
				func(addr tables.NodeAddress) netip.Addr { return addr.Addr },
			),
		)...)

		// Refresh the frontends if the set of NodePort addresses changed
		if !addrs.Equal(newAddrs) {
			err := sr.ServiceManager.SyncNodePortFrontends(newAddrs)
			if err != nil {
				duration := backoff.Duration(retryAttempt)
				retry = time.After(duration)
				retryAttempt++
				sr.Logger.Warn(
					"Could not synchronize new frontend addresses, retrying...",
					logfields.Error, err,
					logfields.Duration, duration,
				)
				health.Degraded("Failed to sync NodePort frontends", err)
			} else {
				addrs = newAddrs
				retryAttempt = 0
				retry = nil
				health.OK(fmt.Sprintf("%d NodePort frontend addresses", len(addrs)))
			}
		}

		select {
		case <-ctx.Done():
			return nil
		case <-watch:
		case <-retry:
		case <-periodicSyncTicker.C:
		}
	}
}
