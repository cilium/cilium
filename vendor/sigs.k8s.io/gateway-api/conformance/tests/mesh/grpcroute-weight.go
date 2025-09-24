/*
Copyright 2025 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package meshtests

import (
	"fmt"
	"testing"

	"sigs.k8s.io/gateway-api/conformance/utils/echo"
	"sigs.k8s.io/gateway-api/conformance/utils/http"
	"sigs.k8s.io/gateway-api/conformance/utils/suite"
	"sigs.k8s.io/gateway-api/conformance/utils/weight"
	"sigs.k8s.io/gateway-api/pkg/features"
)

func init() {
	MeshConformanceTests = append(MeshConformanceTests, MeshGRPCRouteWeight)
}

var MeshGRPCRouteWeight = suite.ConformanceTest{
	ShortName:   "MeshGRPCRouteWeight",
	Description: "A GRPCRoute with weighted backends in mesh mode",
	Manifests:   []string{"tests/mesh/grpcroute-weight.yaml"},
	Features: []features.FeatureName{
		features.SupportMesh,
		features.SupportGRPCRoute,
	},
	Test: func(t *testing.T, s *suite.ConformanceTestSuite) {
		client := echo.ConnectToApp(t, s, echo.MeshAppEchoV1)

		t.Run("Requests should have a distribution that matches the weight", func(t *testing.T) {
			// Create a gRPC request using the mesh client framework
			expected := http.ExpectedResponse{
				Request:   http.Request{Protocol: "grpc", Path: "", Host: "echo:7070"},
				Response:  http.Response{StatusCode: 200},
				Namespace: "gateway-conformance-mesh",
			}

			// Assert request succeeds before doing our distribution check
			client.MakeRequestAndExpectEventuallyConsistentResponse(t, expected, s.TimeoutConfig)

			expectedWeights := map[string]float64{
				"echo-v1": 0.7,
				"echo-v2": 0.3,
			}

			sender := weight.NewFunctionBasedSender(func() (string, error) {
				uniqueExpected := expected
				if err := http.AddEntropy(&uniqueExpected); err != nil {
					return "", fmt.Errorf("error adding entropy: %w", err)
				}
				_, cRes, err := client.CaptureRequestResponseAndCompare(t, uniqueExpected)
				if err != nil {
					return "", fmt.Errorf("failed gRPC mesh request: %w", err)
				}
				return cRes.Hostname, nil
			})

			for i := 0; i < weight.MaxTestRetries; i++ {
				if err := weight.TestWeightedDistribution(sender, expectedWeights); err != nil {
					t.Logf("Traffic distribution test failed (%d/%d): %s", i+1, weight.MaxTestRetries, err)
				} else {
					return
				}
			}
			t.Fatal("Weighted distribution tests failed")
		})
	},
}
