// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package clustermesh

import (
	"errors"

	"github.com/cilium/hive/cell"

	cmk8s "github.com/cilium/cilium/clustermesh-apiserver/clustermesh/k8s"
	"github.com/cilium/cilium/clustermesh-apiserver/option"
	"github.com/cilium/cilium/clustermesh-apiserver/syncstate"
	operatorWatchers "github.com/cilium/cilium/operator/watchers"
	clustercfgcell "github.com/cilium/cilium/pkg/clustermesh/clustercfg/cell"
	"github.com/cilium/cilium/pkg/clustermesh/mcsapi"
	mcsapitypes "github.com/cilium/cilium/pkg/clustermesh/mcsapi/types"
	cmnamespace "github.com/cilium/cilium/pkg/clustermesh/namespace"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/gops"
	cilium_api_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	cilium_api_v2a1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/synced"
	"github.com/cilium/cilium/pkg/k8s/types"
	"github.com/cilium/cilium/pkg/kvstore/heartbeat"
	"github.com/cilium/cilium/pkg/pprof"
)

var Cell = cell.Module(
	"clustermesh",
	"Cilium ClusterMesh",

	cell.Config(mcsapitypes.DefaultMCSAPIConfig),

	pprof.Cell(pprofConfig),
	gops.Cell(defaults.EnableGops, defaults.GopsPortApiserver),

	k8sClient.Cell,
	cmk8s.ResourcesCell,
	cell.Invoke(registerClientsetValidator),

	// Shared synchronization structures for waiting on K8s resources to
	// be synced
	synced.Cell,

	// Provide CRD resource names for 'synced.CRDSyncCell' below.
	cell.Provide(func() synced.CRDSyncResourceNames { return synced.ClusterMeshAPIServerResourceNames() }),

	// CRDSyncCell provides a promise that is resolved as soon as CRDs used by the
	// clustermesh-apiserver have synced.
	// Allows cells to wait for CRDs before trying to list Cilium resources.
	synced.CRDSyncCell,

	heartbeat.Enabled,
	heartbeat.Cell,

	HealthAPIEndpointsCell,

	clustercfgcell.WithSyncedCanaries(true),
	clustercfgcell.Cell,

	Synchronization,

	usersManagementCell,
)

var Synchronization = cell.Module(
	"clustermesh-synchronization",
	"Synchronize information from Kubernetes to KVStore",

	// Provide the namespace manager.
	cmnamespace.Cell,

	cell.Group(
		cell.Provide(
			func(syncState syncstate.SyncState) operatorWatchers.ServiceSyncConfig {
				return operatorWatchers.ServiceSyncConfig{
					Enabled: true,
					Synced:  syncState.WaitForResource(),
				}
			},
		),
		operatorWatchers.ServiceSyncCell,
	),

	cell.Group(
		cell.Provide(
			func(syncState syncstate.SyncState) mcsapi.ServiceExportSyncCallback {
				return syncState.WaitForResource()
			},
		),
		mcsapi.ServiceExportSyncCell,
	),

	cell.Group(
		cell.Provide(
			newCiliumNodeOptions,
			newCiliumNodeConverter,
		),
		cell.Invoke(RegisterSynchronizer[*cilium_api_v2.CiliumNode]),
	),

	cell.Group(
		cell.Provide(
			newCiliumIdentityOptions,
			newCiliumIdentityConverter,
			newCiliumIdentityNamespacer,
		),
		cell.Invoke(RegisterSynchronizer[*cilium_api_v2.CiliumIdentity]),
	),

	cell.Group(
		cell.Provide(
			newCiliumEndpointOptions,
			newCiliumEndpointConverter,
			newCiliumEndpointNamespacer,
		),
		cell.Invoke(RegisterSynchronizer[*types.CiliumEndpoint]),
	),

	cell.Group(
		cell.Provide(
			newCiliumEndpointSliceOptions,
			newCiliumEndpointSliceConverter,
			newCiliumEndpointSliceNamespacer,
		),
		cell.Invoke(RegisterSynchronizer[*cilium_api_v2a1.CiliumEndpointSlice]),
	),
	cell.Invoke(registerSyncStateStop),
)

func registerSyncStateStop(lc cell.Lifecycle, ss syncstate.SyncState) {
	lc.Append(
		cell.Hook{
			OnStart: func(cell.HookContext) error {
				ss.Stop()
				return nil
			},
		},
	)
}

func registerClientsetValidator(lc cell.Lifecycle, client k8sClient.Clientset) {
	lc.Append(cell.Hook{
		// Executed inside a start hook to avoid blocking when the hive is not
		// actually started (e.g., the dependency graph is output).
		OnStart: func(cell.HookContext) error {
			if !client.IsEnabled() {
				return errors.New("Kubernetes client not configured, cannot continue")
			}
			return nil
		},
	})
}

var pprofConfig = pprof.Config{
	Pprof:                     false,
	PprofAddress:              option.PprofAddress,
	PprofPort:                 option.PprofPortClusterMesh,
	PprofMutexProfileFraction: 0,
	PprofBlockProfileRate:     0,
}
