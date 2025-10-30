// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package maps

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"

	datapath "github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/endpointmanager"
	"github.com/cilium/cilium/pkg/endpointstate"
	"github.com/cilium/cilium/pkg/kpr"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/promise"
)

var Cell = cell.Module(
	"maps-cleanup",
	"Cleanup of stale and disabled BPF maps",
	cell.Invoke(registerMapSweeper),
)

type mapSweeperParams struct {
	cell.In

	Logger   *slog.Logger
	JobGroup job.Group

	EndpointRestorerPromise promise.Promise[endpointstate.Restorer]
	EndpointManager         endpointmanager.EndpointManager
	BandwidthManager        datapath.BandwidthManager
	LBConfig                loadbalancer.Config
	KPRConfig               kpr.KPRConfig
}

func registerMapSweeper(params mapSweeperParams) {
	ms := newMapSweeper(
		params.Logger,
		&EndpointMapManager{
			logger:          params.Logger,
			EndpointManager: params.EndpointManager,
		},
		params.BandwidthManager,
		params.LBConfig,
		params.KPRConfig)

	params.JobGroup.Add(job.OneShot("cleanup", func(ctx context.Context, health cell.Health) error {
		restorer, err := params.EndpointRestorerPromise.Await(ctx)
		if err != nil {
			return fmt.Errorf("failed to wait for endpoint restorer: %w", err)
		}

		if err := restorer.WaitForEndpointRestore(ctx); err != nil {
			return fmt.Errorf("failed to wait for endpoint restoration: %w", err)
		}

		ms.CollectStaleMapGarbage()
		ms.RemoveDisabledMaps()

		return nil
	}))
}
