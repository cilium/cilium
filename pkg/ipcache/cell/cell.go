// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipcachecell

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"

	policyapi "github.com/cilium/cilium/api/v1/server/restapi/policy"
	"github.com/cilium/cilium/pkg/endpoint/regeneration"
	"github.com/cilium/cilium/pkg/endpointmanager"
	"github.com/cilium/cilium/pkg/endpointstate"
	"github.com/cilium/cilium/pkg/identity/cache"
	identitycell "github.com/cilium/cilium/pkg/identity/cache/cell"
	"github.com/cilium/cilium/pkg/ipcache"
	"github.com/cilium/cilium/pkg/ipcache/api"
	restoration "github.com/cilium/cilium/pkg/ipcache/restore"
	"github.com/cilium/cilium/pkg/k8s/synced"
	"github.com/cilium/cilium/pkg/logging/logfields"
	ipcachemap "github.com/cilium/cilium/pkg/maps/ipcache"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/option"
	policycell "github.com/cilium/cilium/pkg/policy/cell"
	"github.com/cilium/cilium/pkg/promise"
	"github.com/cilium/cilium/pkg/time"
)

// Cell provides the IPCache that manages the IP to identity mappings.
var Cell = cell.Module(
	"ipcache",
	"Managing IP to identity mappings",

	cell.Provide(
		newIPCache,
		ipcache.NewLocalIPIdentityWatcher,
		ipcache.NewIPIdentitySynchronizer,
		newIPCacheAPIHandler,
	),

	// LocalIdentityRestorer restores the identities at startup
	restoration.Cell,

	cell.Invoke(
		// Register the watcher to the fence to ensure that we wait for ipcache
		// synchronization from the kvstore (when enabled) before endpoint
		// regeneration, to ensure that the ipcache map is ready at that point.
		func(watcher *ipcache.LocalIPIdentityWatcher, fence regeneration.Fence) {
			fence.Add("kvstore-ipcache", watcher.WaitForSync)
		},

		// Register a job to associate default/kubernetes backend IPs with the
		// 'reserved:kube-apiserver' label.
		registerAPIServerBackendWatcher,
	),
)

type ipCacheParams struct {
	cell.In

	Logger                 *slog.Logger
	Lifecycle              cell.Lifecycle
	JobGroup               job.Group
	DaemonConfig           *option.DaemonConfig
	MetricsRegistry        *metrics.Registry
	IdentityRestorer       *restoration.LocalIdentityRestorer
	CacheIdentityAllocator cache.IdentityAllocator
	IdentityUpdater        policycell.IdentityUpdater
	EndpointManager        endpointmanager.EndpointManager
	EndpointRestorePromise promise.Promise[endpointstate.Restorer]
	CacheStatus            synced.CacheStatus
}

func newIPCache(params ipCacheParams) *ipcache.IPCache {
	ctx, cancel := context.WithCancel(context.Background())

	// IPCache: aggregates node-local prefix labels and allocates
	// local identities. Generates incremental updates, pushes
	// to endpoints.
	ipc := ipcache.NewIPCache(&ipcache.Configuration{
		Context:           ctx,
		Logger:            params.Logger,
		IdentityAllocator: params.CacheIdentityAllocator,
		IdentityUpdater:   params.IdentityUpdater,
		CacheStatus:       params.CacheStatus,
	})

	params.Lifecycle.Append(cell.Hook{
		OnStart: func(cell.HookContext) error {
			if params.DaemonConfig.DryMode {
				return nil
			}

			if params.DaemonConfig.RestoreState {
				// Collect CIDR identities from the "old" bpf ipcache and restore them
				// in to the metadata layer.
				// This must be called before re-creating the ipcache map, which will "hide"
				// the "old" ipcache.
				if err := params.IdentityRestorer.RestoreLocalIdentities(ipc); err != nil {
					params.Logger.Warn("Failed to restore existing identities from the previous ipcache. This may cause policy interruptions during restart.", logfields.Error, err)
				}
			}

			// The ipcache is shared between endpoints. Unpin the old ipcache map created
			// by any previous instances of the agent to prevent new endpoints from
			// picking up the old map pin. The old ipcache will continue to be used by
			// loaded bpf programs, it will just no longer be updated by the agent.
			//
			// This is to allow existing endpoints that have not been regenerated yet to
			// continue using the existing ipcache until the endpoint is regenerated for
			// the first time and its bpf programs have been replaced. Existing endpoints
			// are using a policy map which is potentially out of sync as local identities
			// are re-allocated on startup.
			if err := ipcachemap.IPCacheMap(params.MetricsRegistry).Recreate(); err != nil {
				return fmt.Errorf("initializing ipcache map: %w", err)
			}

			return nil
		},
		OnStop: func(hc cell.HookContext) error {
			cancel()
			return ipc.Shutdown()
		},
	})

	params.JobGroup.Add(job.OneShot("release-local-identities", func(ctx context.Context, _ cell.Health) error {
		r, err := params.EndpointRestorePromise.Await(ctx)
		if err != nil {
			return fmt.Errorf("failed to wait for endpoint restorer promise: %w", err)
		}

		if err := r.WaitForEndpointRestore(ctx); err != nil {
			return fmt.Errorf("failed to wait for endpoint restoration: %w", err)
		}

		// Wait for the --identity-restore-grace-period (default: 30 seconds k8s, 10 minutes kvstore), allowing
		// the normal allocation processes to finish, before releasing restored resources.
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(params.DaemonConfig.IdentityRestoreGracePeriod):
		}

		params.IdentityRestorer.ReleaseRestoredIdentities(ipc)

		return nil
	}))

	return ipc
}

type ipcacheAPIHandlerParams struct {
	cell.In

	IPCache           *ipcache.IPCache
	IdentityAllocator identitycell.CachingIdentityAllocator
}

type ipcacheAPIHandlerOut struct {
	cell.Out

	PolicyGetIPHandler policyapi.GetIPHandler
}

func newIPCacheAPIHandler(params ipcacheAPIHandlerParams) ipcacheAPIHandlerOut {
	return ipcacheAPIHandlerOut{
		PolicyGetIPHandler: api.NewIPCacheGetIPHandler(params.IPCache, params.IdentityAllocator),
	}
}
