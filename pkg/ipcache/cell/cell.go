// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipcachecell

import (
	"context"

	"github.com/cilium/hive/cell"

	policyapi "github.com/cilium/cilium/api/v1/server/restapi/policy"
	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/endpointmanager"
	"github.com/cilium/cilium/pkg/identity/cache"
	identitycell "github.com/cilium/cilium/pkg/identity/cache/cell"
	"github.com/cilium/cilium/pkg/ipcache"
	"github.com/cilium/cilium/pkg/ipcache/api"
	"github.com/cilium/cilium/pkg/k8s/synced"
	"github.com/cilium/cilium/pkg/kvstore/store"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/source"
)

// Cell provides the IPCache that manages the IP to identity mappings.
var Cell = cell.Module(
	"ipcache",
	"Managing IP to identity mappings",

	cell.Provide(
		newIPCache,
		newIPIdentityWatcher,
		ipcache.NewIPIdentitySynchronizer,
		newIPCacheAPIHandler,
	),
)

type ipCacheParams struct {
	cell.In

	Lifecycle              cell.Lifecycle
	CacheIdentityAllocator cache.IdentityAllocator
	PolicyRepository       policy.PolicyRepository
	PolicyUpdater          *policy.Updater
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
		IdentityAllocator: params.CacheIdentityAllocator,
		PolicyHandler:     params.PolicyRepository.GetSelectorCache(),
		PolicyUpdater:     params.PolicyUpdater,
		DatapathHandler:   params.EndpointManager,
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

func newIPIdentityWatcher(in struct {
	cell.In

	ClusterInfo cmtypes.ClusterInfo
	IPCache     *ipcache.IPCache
	Factory     store.Factory
},
) *ipcache.IPIdentityWatcher {
	return ipcache.NewIPIdentityWatcher(in.ClusterInfo.Name, in.IPCache, in.Factory, source.KVStore)
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
