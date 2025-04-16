// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package reflectors

import (
	"github.com/cilium/hive/cell"
	"github.com/cilium/stream"

	"github.com/cilium/cilium/pkg/k8s"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
)

var Cell = cell.Module(
	"loadbalancer-reflectors",
	"Reflects external state to load-balancing tables",

	// Bridge Resource[XYZ] to Observable[Event[XYZ]]. Makes it easier to
	// test [ReflectorCell].
	cell.ProvidePrivate(resourcesToStreams),

	cell.Invoke(RegisterK8sReflector),
)

type resourceIn struct {
	cell.In
	ServicesResource  resource.Resource[*slim_corev1.Service]
	EndpointsResource resource.Resource[*k8s.Endpoints]
}

type StreamsOut struct {
	cell.Out
	ServicesStream  stream.Observable[resource.Event[*slim_corev1.Service]]
	EndpointsStream stream.Observable[resource.Event[*k8s.Endpoints]]
}

// resourcesToStreams extracts the stream.Observable from resource.Resource.
// This makes the reflector easier to test as its API surface is reduced.
func resourcesToStreams(in resourceIn) StreamsOut {
	return StreamsOut{
		ServicesStream:  in.ServicesResource,
		EndpointsStream: in.EndpointsResource,
	}
}
