// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package envoy

import (
	"fmt"
	"io"
	"log/slog"
	"testing"

	envoy_config_cluster "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	envoy_config_endpoint "github.com/envoyproxy/go-control-plane/envoy/config/endpoint/v3"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/cilium/cilium/pkg/crypto/certificatemanager"
	"github.com/cilium/cilium/pkg/envoy/config"
	"github.com/cilium/cilium/pkg/envoy/xds"
)

func newDeltaServerBenchmark(b *testing.B, mode config.XDSMode) XDSServer {
	b.Helper()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	serverConfig := xdsServerConfig{
		envoyXDSMode: mode,
		metrics:      xds.NewXDSMetric(),
	}
	secretManager := certificatemanager.NewMockSecretManagerSDS()
	localEndpointStore := newLocalEndpointStore()

	if mode.IsADS() {
		return newADSServer(logger, nil, localEndpointStore, serverConfig, secretManager, nil)
	}
	return newXDSServer(logger, nil, nil, localEndpointStore, serverConfig, secretManager)
}

func benchmarkEndpoint(name string, generation uint32) *envoy_config_endpoint.ClusterLoadAssignment {
	return &envoy_config_endpoint.ClusterLoadAssignment{
		ClusterName: name,
		Policy: &envoy_config_endpoint.ClusterLoadAssignment_Policy{
			OverprovisioningFactor: wrapperspb.UInt32(140 + generation),
		},
	}
}

func benchmarkInitialResources(resourceCount int) xds.Resources {
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
		resources.Endpoints[name] = benchmarkEndpoint(name, 1)
	}
	return resources
}

func benchmarkEndpointUpdate(batchSize int, generation uint32) xds.Resources {
	resources := xds.NewResources()
	for i := range batchSize {
		name := fmt.Sprintf("cluster-%06d", i)
		resources.Endpoints[name] = benchmarkEndpoint(name, generation)
	}
	return resources
}

func BenchmarkDeltaServerEndpointUpdate(b *testing.B) {
	testCases := []struct {
		resourceCount int
		batchSize     int
	}{
		{resourceCount: 100, batchSize: 1},
		{resourceCount: 1_000, batchSize: 1},
		{resourceCount: 1_000, batchSize: 100},
		{resourceCount: 10_000, batchSize: 1},
		{resourceCount: 10_000, batchSize: 100},
	}

	for _, testCase := range testCases {
		for _, mode := range []config.XDSMode{
			config.EnvoyXDSModeDeltaSplit,
			config.EnvoyXDSModeDeltaADS,
		} {
			name := fmt.Sprintf("%s/resources=%d/batch=%d", mode, testCase.resourceCount, testCase.batchSize)
			b.Run(name, func(b *testing.B) {
				server := newDeltaServerBenchmark(b, mode)
				if err := server.UpsertEnvoyResources(b.Context(), benchmarkInitialResources(testCase.resourceCount), nil); err != nil {
					b.Fatal(err)
				}

				oldResources := benchmarkEndpointUpdate(testCase.batchSize, 1)
				newResources := benchmarkEndpointUpdate(testCase.batchSize, 2)
				b.ReportAllocs()
				b.ReportMetric(float64(testCase.resourceCount), "resources")
				b.ReportMetric(float64(testCase.batchSize), "changed_resources")
				b.ResetTimer()

				for b.Loop() {
					if err := server.UpdateEnvoyResources(b.Context(), oldResources, newResources, nil); err != nil {
						b.Fatal(err)
					}
					oldResources, newResources = newResources, oldResources
				}
			})
		}
	}
}
