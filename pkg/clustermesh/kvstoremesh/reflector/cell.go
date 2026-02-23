// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package reflector

import (
	"path"

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
			WithStatePrefixOverride(path.Join(ipcache.IPIdentitiesPath, ipcache.DefaultAddressSpace)),
		)),

		Out(NewFactory(Identities, cache.IdentitiesPath,
			WithStatePrefixOverride(path.Join(cache.IdentitiesPath, "id")),
			WithCachePrefixOverride(path.Join(kvstore.StateToCachePrefix(cache.IdentitiesPath), ClusterNamePlaceHolder, "id")),
		)),

		Out(NewFactory(Nodes, node.NodeStorePrefix)),

		Out(NewFactory(Services, service.ServiceStorePrefix,
			WithRevocation(),
		)),

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
