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

package tests

import (
	"fmt"
	"testing"

	"google.golang.org/grpc/codes"
	"k8s.io/apimachinery/pkg/types"

	v1 "sigs.k8s.io/gateway-api/apis/v1"
	pb "sigs.k8s.io/gateway-api/conformance/echo-basic/grpcechoserver"
	"sigs.k8s.io/gateway-api/conformance/utils/grpc"
	"sigs.k8s.io/gateway-api/conformance/utils/kubernetes"
	"sigs.k8s.io/gateway-api/conformance/utils/suite"
	"sigs.k8s.io/gateway-api/conformance/utils/weight"
	"sigs.k8s.io/gateway-api/pkg/features"
)

func init() {
	ConformanceTests = append(ConformanceTests, GRPCRouteWeight)
}

var GRPCRouteWeight = suite.ConformanceTest{
	ShortName:   "GRPCRouteWeight",
	Description: "A GRPCRoute with weighted backends",
	Manifests:   []string{"tests/grpcroute-weight.yaml"},
	Features: []features.FeatureName{
		features.SupportGateway,
		features.SupportGRPCRoute,
	},
	Test: func(t *testing.T, suite *suite.ConformanceTestSuite) {
		var (
			ns      = "gateway-conformance-infra"
			routeNN = types.NamespacedName{Name: "weighted-backends", Namespace: ns}
			gwNN    = types.NamespacedName{Name: "same-namespace", Namespace: ns}
			gwAddr  = kubernetes.GatewayAndRoutesMustBeAccepted(t, suite.Client, suite.TimeoutConfig, suite.ControllerName, kubernetes.NewGatewayRef(gwNN), &v1.GRPCRoute{}, true, routeNN)
		)

		t.Run("Requests should have a distribution that matches the weight", func(t *testing.T) {
			expected := grpc.ExpectedResponse{
				EchoRequest: &pb.EchoRequest{},
				Response:    grpc.Response{Code: codes.OK},
				Namespace:   "gateway-conformance-infra",
			}

			// Assert request succeeds before doing our distribution check
			grpc.MakeRequestAndExpectEventuallyConsistentResponse(t, suite.GRPCClient, suite.TimeoutConfig, gwAddr, expected)

			expectedWeights := map[string]float64{
				"grpc-infra-backend-v1": 0.7,
				"grpc-infra-backend-v2": 0.3,
				"grpc-infra-backend-v3": 0.0,
			}

			sender := weight.NewFunctionBasedSender(func() (string, error) {
				uniqueExpected := expected
				if err := grpc.AddEntropy(&uniqueExpected); err != nil {
					return "", fmt.Errorf("error adding entropy: %w", err)
				}
				client := &grpc.DefaultClient{}
				defer client.Close()
				resp, err := client.SendRPC(t, gwAddr, uniqueExpected, suite.TimeoutConfig.MaxTimeToConsistency)
				if err != nil {
					return "", fmt.Errorf("failed to send gRPC request: %w", err)
				}
				if resp.Code != codes.OK {
					return "", fmt.Errorf("expected OK response, got %v", resp.Code)
				}
				return resp.Response.GetAssertions().GetContext().GetPod(), nil
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
