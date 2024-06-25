// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package clustermesh

import (
	"github.com/cilium/hive/cell"

	cmk8s "github.com/cilium/cilium/clustermesh-apiserver/clustermesh/k8s"
	"github.com/cilium/cilium/clustermesh-apiserver/health"
	cmmetrics "github.com/cilium/cilium/clustermesh-apiserver/metrics"
	"github.com/cilium/cilium/clustermesh-apiserver/option"
	"github.com/cilium/cilium/clustermesh-apiserver/syncstate"
	"github.com/cilium/cilium/pkg/clustermesh/operator"
	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/controller"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/gops"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/synced"
	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/kvstore/heartbeat"
	"github.com/cilium/cilium/pkg/kvstore/store"
	"github.com/cilium/cilium/pkg/pprof"
)

var Cell = cell.Module(
	"clustermesh",
	"Cilium ClusterMesh",

	cell.Config(option.DefaultLegacyClusterMeshConfig),
	cell.Config(operator.MCSAPIConfig{}),

	// We don't validate that the ClusterID is different from 0 (and the
	// ClusterName is not the default one), because they are valid in
	// case we only use the external workloads feature, and not clustermesh.
	cell.Config(cmtypes.DefaultClusterInfo),
	cell.Invoke(cmtypes.ClusterInfo.InitClusterIDMax),
	cell.Invoke(cmtypes.ClusterInfo.Validate),

	pprof.Cell,
	cell.Config(pprof.Config{
		PprofAddress: option.PprofAddress,
		PprofPort:    option.PprofPortClusterMesh,
	}),
	controller.Cell,

	gops.Cell(defaults.GopsPortApiserver),

	k8sClient.Cell,
	cmk8s.ResourcesCell,

	kvstore.Cell(kvstore.EtcdBackendName),
	cell.Provide(func(ss syncstate.SyncState) *kvstore.ExtraOptions {
		return &kvstore.ExtraOptions{
			BootstrapComplete: ss.WaitChannel(),
		}
	}),
	store.Cell,

	// Shared synchronization structures for waiting on K8s resources to
	// be synced
	synced.Cell,

	// Provide CRD resource names for 'synced.CRDSyncCell' below.
	cell.Provide(func() synced.CRDSyncResourceNames { return synced.ClusterMeshAPIServerResourceNames() }),

	// CRDSyncCell provides a promise that is resolved as soon as CRDs used by the
	// clustermesh-apiserver have synced.
	// Allows cells to wait for CRDs before trying to list Cilium resources.
	synced.CRDSyncCell,

	heartbeat.Cell,
	HealthAPIEndpointsCell,
	health.HealthAPIServerCell,

	cmmetrics.Cell,

	usersManagementCell,
	cell.Invoke(registerHooks),
	externalWorkloadsCell,
)
