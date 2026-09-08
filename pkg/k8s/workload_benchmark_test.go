// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package k8s

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cilium/cilium/api/v1/models"
	cilium_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	cilium_v2alpha1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
)

const workloadBenchmarkCESEndpoints = 100

var workloadSerializationSink []byte

func workloadBenchmarkEndpointWorkload(i int) *cilium_v2.EndpointWorkload {
	return &cilium_v2.EndpointWorkload{
		Name: fmt.Sprintf("checkout-%06d", i),
		Kind: "Deployment",
	}
}

func workloadBenchmarkCoreEndpoint(i int, withWorkload bool) cilium_v2alpha1.CoreCiliumEndpoint {
	endpoint := cilium_v2alpha1.CoreCiliumEndpoint{
		Name:       fmt.Sprintf("checkout-%06d-7c9f55d4b9-abcde", i),
		IdentityID: int64(10000 + i),
		PodUID:     fmt.Sprintf("00000000-0000-4000-8000-%012d", i),
		Networking: &cilium_v2.EndpointNetworking{
			Addressing: cilium_v2.AddressPairList{{
				IPV4: fmt.Sprintf("10.244.%d.%d", (i/250)%250, i%250+1),
			}},
			NodeIP: "192.0.2.10",
		},
		NamedPorts: models.NamedPorts{{Name: "http", Port: 8080, Protocol: "TCP"}},
	}
	if withWorkload {
		endpoint.Workload = workloadBenchmarkEndpointWorkload(i)
	}
	return endpoint
}

func workloadBenchmarkCEP(withWorkload bool) *cilium_v2.CiliumEndpoint {
	endpoint := &cilium_v2.CiliumEndpoint{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "checkout-7c9f55d4b9-abcde",
			Namespace: "shop",
		},
		Status: cilium_v2.EndpointStatus{
			Identity:   &cilium_v2.EndpointIdentity{ID: 10000},
			Networking: workloadBenchmarkCoreEndpoint(0, false).Networking,
		},
	}
	if withWorkload {
		endpoint.Status.Workload = workloadBenchmarkEndpointWorkload(0)
	}
	return endpoint
}

func workloadBenchmarkCES(withWorkload bool) *cilium_v2alpha1.CiliumEndpointSlice {
	slice := &cilium_v2alpha1.CiliumEndpointSlice{Namespace: "shop"}
	for i := range workloadBenchmarkCESEndpoints {
		slice.Endpoints = append(slice.Endpoints, workloadBenchmarkCoreEndpoint(i, withWorkload))
	}
	return slice
}

func BenchmarkEndpointWorkloadSerialization(b *testing.B) {
	benchmarks := []struct {
		name      string
		endpoints int
		object    any
	}{
		{name: "CEP/without-workload", endpoints: 1, object: workloadBenchmarkCEP(false)},
		{name: "CEP/with-workload", endpoints: 1, object: workloadBenchmarkCEP(true)},
		{name: "CES/without-workload", endpoints: workloadBenchmarkCESEndpoints, object: workloadBenchmarkCES(false)},
		{name: "CES/with-workload", endpoints: workloadBenchmarkCESEndpoints, object: workloadBenchmarkCES(true)},
	}

	for _, benchmark := range benchmarks {
		b.Run(benchmark.name, func(b *testing.B) {
			payload, err := json.Marshal(benchmark.object)
			require.NoError(b, err)
			serializedBytesPerEndpoint := float64(len(payload)) / float64(benchmark.endpoints)
			b.ReportAllocs()
			b.ResetTimer()

			for b.Loop() {
				workloadSerializationSink, err = json.Marshal(benchmark.object)
				if err != nil {
					b.Fatal(err)
				}
			}

			b.ReportMetric(serializedBytesPerEndpoint, "bytes/endpoint")
		})
	}
}
