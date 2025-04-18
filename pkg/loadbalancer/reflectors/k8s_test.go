// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package reflectors

import (
	"log/slog"
	"testing"

	"github.com/cilium/hive/hivetest"

	"github.com/cilium/cilium/pkg/k8s"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	slim_discovery_v1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/discovery/v1"
	"github.com/cilium/cilium/pkg/k8s/testutils"
	"github.com/cilium/cilium/pkg/loadbalancer"
)

var (
	benchmarkExternalConfig = loadbalancer.ExternalConfig{
		EnableIPv4:                      true,
		EnableIPv6:                      true,
		ExternalClusterIP:               true,
		EnableHealthCheckNodePort:       true,
		KubeProxyReplacement:            true,
		NodePortMin:                     10000,
		NodePortMax:                     30000,
		NodePortAlg:                     "random",
		LoadBalancerAlgorithmAnnotation: false,
	}
)

func BenchmarkConvertService(b *testing.B) {
	obj, err := testutils.DecodeFile("../experimental/benchmark/testdata/service.yaml")
	if err != nil {
		panic(err)
	}
	svc := obj.(*slim_corev1.Service)

	for b.Loop() {
		convertService(benchmarkExternalConfig, slog.New(slog.DiscardHandler), svc)
	}
	b.ReportMetric(float64(b.N)/b.Elapsed().Seconds(), "services/sec")
}

func BenchmarkParseEndpointSlice(b *testing.B) {
	obj, err := testutils.DecodeFile("../experimental/benchmark/testdata/endpointslice.yaml")
	if err != nil {
		panic(err)
	}
	epSlice := obj.(*slim_discovery_v1.EndpointSlice)
	logger := hivetest.Logger(b)

	for b.Loop() {
		k8s.ParseEndpointSliceV1(logger, epSlice)
	}
	b.ReportMetric(float64(b.N)/b.Elapsed().Seconds(), "endpointslices/sec")
}

func BenchmarkConvertEndpoints(b *testing.B) {
	obj, err := testutils.DecodeFile("../experimental/benchmark/testdata/endpointslice.yaml")
	if err != nil {
		panic(err)
	}
	epSlice := obj.(*slim_discovery_v1.EndpointSlice)
	logger := hivetest.Logger(b)
	eps := k8s.ParseEndpointSliceV1(logger, epSlice)

	for b.Loop() {
		convertEndpoints(benchmarkExternalConfig, eps)
	}
	b.ReportMetric(float64(b.N)/b.Elapsed().Seconds(), "endpoints/sec")
}
