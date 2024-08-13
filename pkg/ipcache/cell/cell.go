// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipcachecell

import (
	"context"

	"github.com/cilium/hive/cell"

	"github.com/cilium/cilium/pkg/endpointmanager"
	"github.com/cilium/cilium/pkg/identity/cache"
	"github.com/cilium/cilium/pkg/ipcache"
	"github.com/cilium/cilium/pkg/k8s/synced"
	"github.com/cilium/cilium/pkg/policy"
)

// Cell provides the IPCache that manages the IP to identity mappings.
var Cell = cell.Module(
	"ipcache",
	"Managing IP to identity mappings",

	cell.Provide(newIPCache),
)

type ipCacheParams struct {
	cell.In

	Lifecycle              cell.Lifecycle
	CacheIdentityAllocator cache.IdentityAllocator
	PolicyRepository       *policy.Repository
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
