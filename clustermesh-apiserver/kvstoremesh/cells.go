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

	WithLeaderLifecycle(
		kvstoremesh.Cell,

		cell.Provide(func(kmConfig kvstoremesh.Config) heartbeat.Config {
			return heartbeat.Config{
				EnableHeartBeat: kmConfig.EnableHeartBeat,
			}
		}),
		heartbeat.Cell,

		cell.Provide(kvstoremesh.NewSyncWaiter),
		cell.Invoke(func(*kvstoremesh.KVStoreMesh) {}),
	),

	// This needs to be the last in the list, so that the start hook responsible
	// for leader election is guaranteed to be executed last, when
	// all the previous ones have already completed. Otherwise, cells within
	// the "WithLeaderLifecycle" scope may be incorrectly started too early,
	// given that "registerLeaderElectionHooks" does not depend on all of their
	// individual dependencies outside of that scope.
	cell.Invoke(
		registerLeaderElectionHooks,
	),
)

var pprofConfig = pprof.Config{
	Pprof:                     false,
	PprofAddress:              option.PprofAddress,
	PprofPort:                 option.PprofPortKVStoreMesh,
	PprofMutexProfileFraction: 0,
	PprofBlockProfileRate:     0,
}
