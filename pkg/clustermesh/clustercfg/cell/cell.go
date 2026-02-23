// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package clustercfgcell

import (
	"github.com/cilium/hive/cell"

	"github.com/cilium/cilium/pkg/clustermesh/clustercfg"
	mcsapitypes "github.com/cilium/cilium/pkg/clustermesh/mcsapi/types"
	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
)

// Cell takes care of writing the cluster configuration to the kvstore, and
// automatically reverting possible external modifications.
var Cell = cell.Module(
	"cluster-config-enforcement",
	"Enforce the CiliumClusterConfig in the KVStore",

	cell.Provide(
		func(cinfo cmtypes.ClusterInfo, mcsAPICfg mcsapitypes.MCSAPIConfig, sc syncedCanaries) cmtypes.CiliumClusterConfig {
			return cmtypes.CiliumClusterConfig{
				ID: cinfo.ID,
				Capabilities: cmtypes.CiliumClusterConfigCapabilities{
					SyncedCanaries:        bool(sc),
					MaxConnectedClusters:  cinfo.MaxConnectedClusters,
					ServiceExportsEnabled: &mcsAPICfg.EnableMCSAPI,
				},
			}
		},
	),

	cell.Invoke(clustercfg.RegisterEnforcer),
)

// WithSyncedCanaries configures the SyncedCanaries field of the ClusterConfig.
func WithSyncedCanaries(enabled bool) cell.Cell {
	return cell.Provide(func() syncedCanaries {
		return syncedCanaries(enabled)
	})
}

type syncedCanaries bool
