// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package linux

import (
	"context"
	"fmt"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"

	"github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/node/addressing"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/rate"
	"github.com/cilium/cilium/pkg/time"
)

// BackendNeighborSyncCell watches Table[*loadbalancer.Backend] and inserts/deletes
// the neighbor table entries for each backend address.
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

	JobGroup      job.Group
	DB            *statedb.DB
	NodeNeighbors types.NodeNeighbors
	Backends      statedb.Table[*loadbalancer.Backend]
}

func registerBackendNeighborSync(p backendNeighborSyncParams) {
	p.JobGroup.Add(
		job.OneShot(
			"backend-neighbor-sync",
			func(ctx context.Context, _ cell.Health) error {
				return syncBackendNeighbors(p, ctx)
			},
		))
}

func syncBackendNeighbors(p backendNeighborSyncParams, ctx context.Context) error {
	wtxn := p.DB.WriteTxn(p.Backends)
	changeIter, err := p.Backends.Changes(wtxn)
	wtxn.Commit()
	if err != nil {
		return err
	}

	// Process the changes in batches every 50 milliseconds.
	limiter := rate.NewLimiter(50*time.Millisecond, 1)
	defer limiter.Stop()

	addedNeighbors := map[loadbalancer.L3n4Addr]*nodeTypes.Node{}

	for {
		changes, watch := changeIter.Next(p.DB.ReadTxn())
		for change := range changes {
			n, found := addedNeighbors[change.Object.Address]
			switch {
			case change.Deleted && found:
				delete(addedNeighbors, change.Object.Address)
				p.NodeNeighbors.DeleteMiscNeighbor(n)

			case !change.Deleted && !found:
				n := backendToNode(change.Object)
				addedNeighbors[change.Object.Address] = n
				p.NodeNeighbors.InsertMiscNeighbor(n)
			}
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

func backendToNode(b *loadbalancer.Backend) *nodeTypes.Node {
	return &nodeTypes.Node{
		Name: fmt.Sprintf("backend-%s", b.Address.AddrCluster.AsNetIP()),
		IPAddresses: []nodeTypes.Address{{
			Type: addressing.NodeInternalIP,
			IP:   b.Address.AddrCluster.AsNetIP(),
		}},
	}
}
