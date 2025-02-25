// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package experimental

import (
	"testing"

	"github.com/cilium/cilium/pkg/k8s"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	slim_discovery_v1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/discovery/v1"
	"github.com/cilium/cilium/pkg/k8s/testutils"
)

var (
	benchmarkExternalConfig = ExternalConfig{
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
	obj, err := testutils.DecodeFile("benchmark/testdata/service.yaml")
	if err != nil {
		panic(err)
	}
	svc := obj.(*slim_corev1.Service)

	b.ResetTimer()
	for range b.N {
		convertService(benchmarkExternalConfig, svc)
	}
	b.ReportMetric(float64(b.N)/b.Elapsed().Seconds(), "services/sec")
}

func BenchmarkParseEndpointSlice(b *testing.B) {
	obj, err := testutils.DecodeFile("benchmark/testdata/endpointslice.yaml")
	if err != nil {
		panic(err)
	}
	epSlice := obj.(*slim_discovery_v1.EndpointSlice)

	b.ResetTimer()
	for range b.N {
		k8s.ParseEndpointSliceV1(epSlice)
	}
	b.ReportMetric(float64(b.N)/b.Elapsed().Seconds(), "endpointslices/sec")
}

func BenchmarkConvertEndpoints(b *testing.B) {
	obj, err := testutils.DecodeFile("benchmark/testdata/endpointslice.yaml")
	if err != nil {
		panic(err)
	}
	epSlice := obj.(*slim_discovery_v1.EndpointSlice)
	eps := k8s.ParseEndpointSliceV1(epSlice)

	b.ResetTimer()
	for range b.N {
		convertEndpoints(benchmarkExternalConfig, eps)
	}
	b.ReportMetric(float64(b.N)/b.Elapsed().Seconds(), "endpoints/sec")
}
