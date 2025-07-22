// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package linux

import (
	"context"
	"log/slog"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"

	"github.com/cilium/cilium/pkg/datapath/neighbor"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/rate"
	"github.com/cilium/cilium/pkg/time"
)

// BackendNeighborSyncCell watches Table[*loadbalancer.Backend] and inserts/deletes
// the forwardable IP entries for each backend address.
//
// This is needed by XDP program to be able to resolve the hardware address of
// the backend as it cannot use the neighbor sub-system to resolve it on-demand.
var BackendNeighborSyncCell = cell.Module(
	"backend-neighbor-sync",
	"Synchronizes backends to Linux neighbors table",

	cell.Invoke(registerBackendNeighborSync),
)

type backendNeighborSyncParams struct {
	cell.In

	JobGroup             job.Group
	Logger               *slog.Logger
	DB                   *statedb.DB
	ForwardableIPManager *neighbor.ForwardableIPManager
	Backends             statedb.Table[*loadbalancer.Backend]
}

func registerBackendNeighborSync(p backendNeighborSyncParams) {
	// If the ForwardableIPManager is not enabled, then there is no point in
	// doing any work here.
	if !p.ForwardableIPManager.Enabled() {
		return
	}

	initializer := p.ForwardableIPManager.RegisterInitializer("service-backend-neighbor-sync")

	p.JobGroup.Add(
		job.OneShot(
			"backend-neighbor-sync",
			func(ctx context.Context, _ cell.Health) error {
				return syncBackendNeighbors(p, ctx, initializer)
			},
		))
}

func syncBackendNeighbors(p backendNeighborSyncParams, ctx context.Context, initializer neighbor.ForwardableIPInitializer) error {
	wtxn := p.DB.WriteTxn(p.Backends)
	changeIter, err := p.Backends.Changes(wtxn)
	wtxn.Commit()
	if err != nil {
		return err
	}

	// Process the changes in batches every 50 milliseconds.
	limiter := rate.NewLimiter(50*time.Millisecond, 1)
	defer limiter.Stop()

	for {
		rx := p.DB.ReadTxn()

		changes, watch := changeIter.Next(rx)
		for change := range changes {
			owner := neighbor.ForwardableIPOwner{
				Type: neighbor.ForwardableIPOwnerService,
				ID:   change.Object.Address.StringID(),
			}

			if change.Deleted {
				err := p.ForwardableIPManager.Delete(
					change.Object.Address.Addr(),
					owner,
				)
				if err != nil {
					p.Logger.Error("Failed to delete forwardable IP", logfields.Error, err)
				}
			} else {
				err := p.ForwardableIPManager.Insert(
					change.Object.Address.Addr(),
					owner,
				)
				if err != nil {
					p.Logger.Error("Failed to insert forwardable IP", logfields.Error, err)
				}
			}
		}

		// If the service backends have been initialized, we can finish the
		// initializer of the ForwardableIP table.
		if init, _ := p.Backends.Initialized(rx); init {
			p.ForwardableIPManager.FinishInitializer(initializer)
		}

		select {
		case <-watch:
		case <-ctx.Done():
			return ctx.Err()
		}
		if err := limiter.Wait(ctx); err != nil {
			return err
		}
	}
}
