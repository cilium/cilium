// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package clustermesh

import (
	cmk8s "github.com/cilium/cilium/clustermesh-apiserver/clustermesh/k8s"
	cmmetrics "github.com/cilium/cilium/clustermesh-apiserver/metrics"
	"github.com/cilium/cilium/clustermesh-apiserver/option"
	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/controller"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/gops"
	"github.com/cilium/cilium/pkg/hive/cell"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/kvstore/heartbeat"
	"github.com/cilium/cilium/pkg/kvstore/store"
	"github.com/cilium/cilium/pkg/pprof"
)

var Cell = cell.Module(
	"clustermesh",
	"Cilium ClusterMesh",

	cell.Config(option.DefaultLegacyClusterMeshConfig),

	// We don't validate that the ClusterID is different from 0 (and the
	// ClusterName is not the default one), because they are valid in
	// case we only use the external workloads feature, and not clustermesh.
	cell.Config(cmtypes.DefaultClusterInfo),
	cell.Invoke(func(cinfo cmtypes.ClusterInfo) error { return cinfo.InitClusterIDMax() }),
	cell.Invoke(func(cinfo cmtypes.ClusterInfo) error { return cinfo.Validate() }),

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
	cell.Provide(func() *kvstore.ExtraOptions { return nil }),
	store.Cell,

	heartbeat.Cell,
	healthAPIServerCell,

	cmmetrics.Cell,

	usersManagementCell,
	cell.Invoke(registerHooks),
	externalWorkloadsCell,
)
