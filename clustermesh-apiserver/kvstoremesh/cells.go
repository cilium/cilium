// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package kvstoremesh

import (
	"github.com/cilium/hive/cell"

	"github.com/cilium/cilium/clustermesh-apiserver/health"
	cmmetrics "github.com/cilium/cilium/clustermesh-apiserver/metrics"
	"github.com/cilium/cilium/clustermesh-apiserver/option"
	"github.com/cilium/cilium/clustermesh-apiserver/syncstate"
	"github.com/cilium/cilium/pkg/clustermesh/kvstoremesh"
	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/controller"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/gops"
	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/pprof"
)

var Cell = cell.Module(
	"kvstoremesh",
	"Cilium KVStoreMesh",

	cell.Config(option.DefaultLegacyKVStoreMeshConfig),
	cell.Config(kvstoremesh.DefaultConfig),

	cell.Config(cmtypes.DefaultClusterInfo),
	cell.Invoke(cmtypes.RegisterClusterInfoValidator),

	pprof.Cell,
	cell.Config(pprofConfig),
	controller.Cell,

	gops.Cell(defaults.EnableGops, defaults.GopsPortKVStoreMesh),
	cmmetrics.Cell,

	HealthAPIEndpointsCell,
	health.HealthAPIServerCell,

	APIServerCell,

	kvstore.Cell,
	cell.Provide(func(ss syncstate.SyncState) *kvstore.ExtraOptions {
		return &kvstore.ExtraOptions{
			BootstrapComplete: ss.WaitChannel(),
		}
	}),
	kvstoremesh.Cell,

	cell.Invoke(kvstoremesh.RegisterSyncWaiter),

	cell.Invoke(func(*kvstoremesh.KVStoreMesh) {}),
)

var pprofConfig = pprof.Config{
	Pprof:        false,
	PprofAddress: option.PprofAddress,
	PprofPort:    option.PprofPortKVStoreMesh,
}
