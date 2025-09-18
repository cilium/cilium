// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipcachecell

import (
	"context"
	"log/slog"

	"github.com/cilium/hive/cell"

	policyapi "github.com/cilium/cilium/api/v1/server/restapi/policy"
	"github.com/cilium/cilium/pkg/endpoint/regeneration"
	"github.com/cilium/cilium/pkg/endpointmanager"
	"github.com/cilium/cilium/pkg/identity/cache"
	identitycell "github.com/cilium/cilium/pkg/identity/cache/cell"
	"github.com/cilium/cilium/pkg/ipcache"
	"github.com/cilium/cilium/pkg/ipcache/api"
	"github.com/cilium/cilium/pkg/k8s/synced"
	policycell "github.com/cilium/cilium/pkg/policy/cell"
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

	cell.Invoke(
		// Register the watcher to the fence to ensure that we wait for ipcache
		// synchronization from the kvstore (when enabled) before endpoint
		// regeneration, to ensure that the ipcache map is ready at that point.
		func(watcher *ipcache.LocalIPIdentityWatcher, fence regeneration.Fence) {
			fence.Add("kvstore-ipcache", watcher.WaitForSync)
		},
	),
)

type ipCacheParams struct {
	cell.In

	Logger                 *slog.Logger
	Lifecycle              cell.Lifecycle
	CacheIdentityAllocator cache.IdentityAllocator
	IdentityUpdater        policycell.IdentityUpdater
	EndpointManager        endpointmanager.EndpointManager
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
		OnStop: func(hc cell.HookContext) error {
			cancel()

			return ipc.Shutdown()
		},
	})

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
