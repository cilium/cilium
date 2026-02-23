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
	"testing"

	"k8s.io/apimachinery/pkg/types"

	v1 "sigs.k8s.io/gateway-api/apis/v1"
	pb "sigs.k8s.io/gateway-api/conformance/echo-basic/grpcechoserver"
	"sigs.k8s.io/gateway-api/conformance/utils/grpc"
	"sigs.k8s.io/gateway-api/conformance/utils/kubernetes"
	"sigs.k8s.io/gateway-api/conformance/utils/suite"
	"sigs.k8s.io/gateway-api/pkg/features"
)

func init() {
	ConformanceTests = append(ConformanceTests, GRPCRouteNamedRule)
}

var GRPCRouteNamedRule = suite.ConformanceTest{
	ShortName:   "GRPCRouteNamedRule",
	Description: "A GRPCRoute with a named GRPCRouteRule",
	Manifests:   []string{"tests/grpcroute-named-rule.yaml"},
	Features: []features.FeatureName{
		features.SupportGateway,
		features.SupportGRPCRoute,
		features.SupportGRPCRouteNamedRouteRule,
	},
	Provisional: true,
	Test: func(t *testing.T, suite *suite.ConformanceTestSuite) {
		ns := "gateway-conformance-infra"
		routeNN := types.NamespacedName{Name: "grpc-named-rules", Namespace: ns}
		gwNN := types.NamespacedName{Name: "same-namespace", Namespace: ns}
		gwAddr := kubernetes.GatewayAndRoutesMustBeAccepted(t, suite.Client, suite.TimeoutConfig, suite.ControllerName, kubernetes.NewGatewayRef(gwNN), &v1.GRPCRoute{}, true, routeNN)

		testCases := []grpc.ExpectedResponse{
			{
				EchoRequest: &pb.EchoRequest{},
				Backend:     "grpc-infra-backend-v1",
				Namespace:   ns,
			}, {
				EchoTwoRequest: &pb.EchoRequest{},
				Backend:        "grpc-infra-backend-v2",
				Namespace:      ns,
			},
		}

		for i := range testCases {
			tc := testCases[i]
			t.Run(tc.GetTestCaseName(i), func(t *testing.T) {
				t.Parallel()
				grpc.MakeRequestAndExpectEventuallyConsistentResponse(t, suite.GRPCClient, suite.TimeoutConfig, gwAddr, tc)
			})
		}
	},
}
