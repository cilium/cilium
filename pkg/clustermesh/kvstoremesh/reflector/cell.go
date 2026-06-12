// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package reflector

import (
	"github.com/cilium/hive/cell"

	mcsapi "github.com/cilium/cilium/pkg/clustermesh/mcsapi/types"
	service "github.com/cilium/cilium/pkg/clustermesh/store"
	"github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/identity/cache"
	"github.com/cilium/cilium/pkg/ipcache"
	"github.com/cilium/cilium/pkg/kvstore"
	node "github.com/cilium/cilium/pkg/node/store"
)

var Cell = cell.Group(
	cell.Provide(
		Out(NewFactory(Endpoints, ipcache.IPIdentitiesPath,
			WithStatePrefixOverride(kvstore.JoinKey(ipcache.IPIdentitiesPath, ipcache.DefaultAddressSpace)),
		)),

		Out(NewFactory(Identities, cache.IdentitiesPath,
			WithStatePrefixOverride(kvstore.JoinKey(cache.IdentitiesPath, "id")),
			WithCachePrefixOverride(kvstore.JoinKey(kvstore.StateToCachePrefix(cache.IdentitiesPath), ClusterNamePlaceHolder, "id")),
		)),

		Out(NewFactory(Nodes, node.NodeStorePrefix)),

		func(serviceV2Cfg types.ServiceModeV2Config) out {
			return out{Factory: NewFactory(Services, service.ServiceStorePrefix,
				WithRevocation(),
				WithEnabledOverride(func(cfg types.CiliumClusterConfig) bool {
					if cfg.Capabilities.EndpointSlicesExportMode == types.EndpointSlicesExportModeEndpointSlicesOnly {
						return false
					}
					return serviceV2Cfg.ServiceModeV2.ShouldExportLegacyServices()
				}),
			)}
		},

		Out(NewFactory(ServiceExports, mcsapi.ServiceExportStorePrefix,
			WithRevocation(),
			WithEnabledOverride(func(cfg types.CiliumClusterConfig) bool {
				return cfg.Capabilities.ServiceExportsEnabled != nil
			}),
		)),
	),
)

type out struct {
	cell.Out

	Factory Factory `group:"kvstoremesh-reflectors"`
}

func Out(factory Factory) func() out {
	return func() out { return out{Factory: factory} }
}
