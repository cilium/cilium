// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package experimental

import (
	"github.com/cilium/hive/cell"
	"github.com/cilium/statedb"
	"github.com/cilium/stream"

	daemonK8s "github.com/cilium/cilium/daemon/k8s"
	"github.com/cilium/cilium/pkg/k8s"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
)

var Cell = cell.Module(
	"loadbalancer-experimental",
	"Experimental load-balancing control-plane",

	cell.Config(DefaultConfig),
	cell.ProvidePrivate(newExternalConfig),

	// Provides [Writer] API and the load-balancing tables.
	TablesCell,

	// Reflects Kubernetes services and endpoints to the load-balancing tables
	// using the [Writer].
	ReflectorCell,

	// Bridge Resource[XYZ] to Observable[Event[XYZ]]. Makes it easier to
	// test [ReflectorCell].
	cell.ProvidePrivate(resourcesToStreams),

	// ReconcilerCell reconciles the load-balancing state with the BPF maps.
	ReconcilerCell,

	// Provide [lbmaps], abstraction for the load-balancing BPF map access.
	cell.ProvidePrivate(newLBMaps, newLBMapsConfig),
)

// TablesCell provides the [Writer] API for configuring load-balancing and the
// Table[*Service], Table[*Frontend] and Table[*Backend] for read-only access
// to load-balancing state.
var TablesCell = cell.Module(
	"tables",
	"Experimental load-balancing control-plane",

	// Provide the RWTable[Service] and RWTable[Backend] privately to this
	// module so that the tables are only modified via the Services API.
	cell.ProvidePrivate(
		NewServicesTable,
		NewFrontendsTable,
		NewBackendsTable,
	),

	cell.Provide(
		// Provide the [Writer] API for modifying the tables.
		NewWriter,

		// Provide direct read-only access to the tables.
		statedb.RWTable[*Service].ToTable,
		statedb.RWTable[*Frontend].ToTable,
		statedb.RWTable[*Backend].ToTable,
	),
)

func newLBMaps(lc cell.Lifecycle, cfg LBMapsConfig, w *Writer) LBMaps {
	if !w.IsEnabled() {
		return nil
	}
	r := &BPFLBMaps{Pinned: true, Cfg: cfg}
	lc.Append(r)
	return r
}

type resourceIn struct {
	cell.In
	ServicesResource  resource.Resource[*slim_corev1.Service]
	EndpointsResource resource.Resource[*k8s.Endpoints]
	PodsResource      daemonK8s.LocalPodResource
}

type streamsOut struct {
	cell.Out
	ServicesStream  stream.Observable[resource.Event[*slim_corev1.Service]]
	EndpointsStream stream.Observable[resource.Event[*k8s.Endpoints]]
	PodsStream      stream.Observable[resource.Event[*slim_corev1.Pod]]
}

// resourcesToStreams extracts the stream.Observable from resource.Resource.
// This makes the reflector easier to test as its API surface is reduced.
func resourcesToStreams(in resourceIn) streamsOut {
	return streamsOut{
		ServicesStream:  in.ServicesResource,
		EndpointsStream: in.EndpointsResource,
		PodsStream:      in.PodsResource,
	}
}
