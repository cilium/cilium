// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package kvstoremesh

import (
	"github.com/cilium/hive/cell"

	"github.com/cilium/cilium/clustermesh-apiserver/option"
	"github.com/cilium/cilium/pkg/clustermesh/kvstoremesh"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/gops"
	"github.com/cilium/cilium/pkg/kvstore/heartbeat"
	"github.com/cilium/cilium/pkg/pprof"
)

var Cell = cell.Module(
	"kvstoremesh",
	"Cilium KVStoreMesh",

	cell.Config(kvstoremesh.DefaultConfig),

	pprof.Cell(pprofConfig),
	gops.Cell(defaults.EnableGops, defaults.GopsPortKVStoreMesh),

	HealthAPIEndpointsCell,

	APIServerCell,

	kvstoremesh.Cell,

	cell.Provide(func(kmConfig kvstoremesh.Config) heartbeat.Config {
		return heartbeat.Config{
			EnableHeartBeat: kmConfig.EnableHeartBeat,
		}
	}),
	heartbeat.Cell,

	cell.Invoke(kvstoremesh.RegisterSyncWaiter),

	cell.Invoke(func(*kvstoremesh.KVStoreMesh) {}),
)

var pprofConfig = pprof.Config{
	Pprof:        false,
	PprofAddress: option.PprofAddress,
	PprofPort:    option.PprofPortKVStoreMesh,
}
