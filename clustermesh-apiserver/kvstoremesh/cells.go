// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package kvstoremesh

import (
	cmmetrics "github.com/cilium/cilium/clustermesh-apiserver/metrics"
	"github.com/cilium/cilium/clustermesh-apiserver/option"
	"github.com/cilium/cilium/pkg/clustermesh/kvstoremesh"
	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/controller"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/gops"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/pprof"
)

var Cell = cell.Module(
	"kvstoremesh",
	"Cilium KVStoreMesh",

	cell.Config(option.DefaultLegacyKVStoreMeshConfig),

	cell.Config(cmtypes.DefaultClusterInfo),
	cell.Invoke(registerClusterInfoValidator),

	pprof.Cell,
	cell.Config(pprof.Config{
		PprofAddress: option.PprofAddress,
		PprofPort:    option.PprofPortKVStoreMesh,
	}),
	controller.Cell,

	gops.Cell(defaults.GopsPortKVStoreMesh),
	cmmetrics.Cell,

	kvstore.Cell(kvstore.EtcdBackendName),
	cell.Provide(func() *kvstore.ExtraOptions { return nil }),
	kvstoremesh.Cell,

	cell.Invoke(func(*kvstoremesh.KVStoreMesh) {}),
)
