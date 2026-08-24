// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package xdsnew

import (
	"fmt"
	"io"
	"log/slog"
	"testing"

	envoy_config_cluster "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	envoy_config_endpoint "github.com/envoyproxy/go-control-plane/envoy/config/endpoint/v3"
	cache "github.com/envoyproxy/go-control-plane/pkg/cache/v3"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/cilium/cilium/pkg/envoy/xds"
)

var benchmarkSnapshotSink cache.ResourceSnapshot

func benchmarkSnapshotResources(resourceCount int, firstGeneration uint32) *xds.Resources {
	resources := xds.NewResources()
	for i := range resourceCount {
		name := fmt.Sprintf("cluster-%06d", i)
		resources.Clusters[name] = &envoy_config_cluster.Cluster{
			Name: name,
			ClusterDiscoveryType: &envoy_config_cluster.Cluster_Type{
				Type: envoy_config_cluster.Cluster_EDS,
			},
			EdsClusterConfig: &envoy_config_cluster.Cluster_EdsClusterConfig{ServiceName: name},
		}
		generation := uint32(1)
		if i == 0 {
			generation = firstGeneration
		}
		resources.Endpoints[name] = &envoy_config_endpoint.ClusterLoadAssignment{
			ClusterName: name,
			Policy: &envoy_config_endpoint.ClusterLoadAssignment_Policy{
				OverprovisioningFactor: wrapperspb.UInt32(140 + generation),
			},
		}
	}
	return &resources
}

func BenchmarkGenerateSnapshotSparseEndpointUpdate(b *testing.B) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	for _, resourceCount := range []int{100, 1_000, 10_000} {
		b.Run(fmt.Sprintf("resources=%d", resourceCount), func(b *testing.B) {
			snapshotCache := NewCache(logger, true)
			stateA := benchmarkSnapshotResources(resourceCount, 1)
			stateB := benchmarkSnapshotResources(resourceCount, 2)
			resources := stateA
			var err error

			b.ReportAllocs()
			b.ReportMetric(float64(resourceCount), "resources")
			b.ResetTimer()
			for b.Loop() {
				benchmarkSnapshotSink, err = snapshotCache.GenerateSnapshot(resources, logger)
				if err != nil {
					b.Fatal(err)
				}
				if resources == stateA {
					resources = stateB
				} else {
					resources = stateA
				}
			}
		})
	}
}
