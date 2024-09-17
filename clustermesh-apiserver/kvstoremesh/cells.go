// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package kvstoremesh

import (
	"github.com/cilium/hive/cell"

	"google.golang.org/grpc"

	"github.com/cilium/cilium/clustermesh-apiserver/health"
	cmmetrics "github.com/cilium/cilium/clustermesh-apiserver/metrics"
	"github.com/cilium/cilium/clustermesh-apiserver/option"
	"github.com/cilium/cilium/clustermesh-apiserver/syncstate"
	"github.com/cilium/cilium/pkg/clustermesh/kvstoremesh"
	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/controller"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/dial"
	"github.com/cilium/cilium/pkg/gops"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/pprof"
)

var Cell = cell.Module(
	"kvstoremesh",
	"Cilium KVStoreMesh",

	cell.Config(option.DefaultLegacyKVStoreMeshConfig),
	cell.Config(kvstoremesh.DefaultConfig),

	cell.Config(cmtypes.DefaultClusterInfo),
	cell.Invoke(registerClusterInfoValidator),

	pprof.Cell,
	cell.Config(pprofConfig),
	controller.Cell,

	gops.Cell(defaults.GopsPortKVStoreMesh),
	cmmetrics.Cell,

	HealthAPIEndpointsCell,
	health.HealthAPIServerCell,

	APIServerCell,

	kvstore.Cell,
	k8sClient.Cell,
	dial.ClustermeshResolverCell,
	cell.Provide(func(ss syncstate.SyncState, cmResolver *dial.ClustermeshResolver) *kvstore.ExtraOptions {
		return &kvstore.ExtraOptions{
			DialOption: []grpc.DialOption{
				grpc.WithContextDialer(dial.NewContextDialer(log, cmResolver)),
			},
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
