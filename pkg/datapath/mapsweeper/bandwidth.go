// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package mapsweeper

import (
	"context"
	"fmt"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"

	bandwidthTypes "github.com/cilium/cilium/pkg/datapath/linux/bandwidth/types"
	"github.com/cilium/cilium/pkg/endpointstate"
	"github.com/cilium/cilium/pkg/maps/bwmap"
	"github.com/cilium/cilium/pkg/promise"
)

// bandwidthEdtInitializerName is the name of the Table[bwmap.Edt]
// initializer that is pending until endpoint restoration has completed.
const bandwidthEdtInitializerName = "endpoint-restoration"

type bandwidthEdtInitializerParams struct {
	cell.In

	JobGroup                job.Group
	DB                      *statedb.DB
	BandwidthConfig         bandwidthTypes.Config
	EdtTable                statedb.RWTable[bwmap.Edt]
	EndpointRestorerPromise promise.Promise[endpointstate.Restorer]
}

// registerBandwidthEdtInitializer holds off the initialization of
// Table[bwmap.Edt] until the endpoints of the previous agent run have been
// restored and regenerated.
//
// Once the table is initialized, its reconciler prunes every cilium_throttle
// entry that has no corresponding object in the table. Restored endpoints
// re-insert their bandwidth limits only after they have resolved their pod
// metadata, so pruning any earlier would remove the bandwidth limits of all
// running pods on every agent restart and leave their traffic unpaced until
// the limits are re-applied.
func registerBandwidthEdtInitializer(p bandwidthEdtInitializerParams) {
	if !p.BandwidthConfig.EnableBandwidthManager {
		return
	}

	wtxn := p.DB.WriteTxn(p.EdtTable)
	initDone := p.EdtTable.RegisterInitializer(wtxn, bandwidthEdtInitializerName)
	wtxn.Commit()

	p.JobGroup.Add(job.OneShot("bandwidth-edt-initializer", func(ctx context.Context, _ cell.Health) error {
		restorer, err := p.EndpointRestorerPromise.Await(ctx)
		if err != nil {
			return fmt.Errorf("failed to wait for endpoint restorer: %w", err)
		}

		// Do not mark the table initialized when restoration did not finish
		// (the agent is stopping), as that would prune the entries of the
		// endpoints that were not restored yet.
		if err := restorer.WaitForEndpointRestore(ctx); err != nil {
			return fmt.Errorf("failed to wait for endpoint restoration: %w", err)
		}

		wtxn := p.DB.WriteTxn(p.EdtTable)
		initDone(wtxn)
		wtxn.Commit()

		return nil
	}))
}
