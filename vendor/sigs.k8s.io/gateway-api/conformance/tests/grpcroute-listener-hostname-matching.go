/*
Copyright 2024 The Kubernetes Authors.

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

	"google.golang.org/grpc/codes"
	"k8s.io/apimachinery/pkg/types"

	v1 "sigs.k8s.io/gateway-api/apis/v1"
	pb "sigs.k8s.io/gateway-api/conformance/echo-basic/grpcechoserver"
	"sigs.k8s.io/gateway-api/conformance/utils/grpc"
	"sigs.k8s.io/gateway-api/conformance/utils/kubernetes"
	"sigs.k8s.io/gateway-api/conformance/utils/suite"
	"sigs.k8s.io/gateway-api/pkg/features"
)

func init() {
	ConformanceTests = append(ConformanceTests, GRPCRouteListenerHostnameMatching)
}

var GRPCRouteListenerHostnameMatching = suite.ConformanceTest{
	ShortName:   "GRPCRouteListenerHostnameMatching",
	Description: "Multiple GRPC listeners with the same port and different hostnames, each with a different GRPCRoute",
	Manifests:   []string{"tests/grpcroute-listener-hostname-matching.yaml"},
	Features: []features.FeatureName{
		features.SupportGateway,
		features.SupportGRPCRoute,
	},
	Test: func(t *testing.T, suite *suite.ConformanceTestSuite) {
		ns := "gateway-conformance-infra"

		// This test creates an additional Gateway in the gateway-conformance-infra
		// namespace so we have to wait for it to be ready.
		kubernetes.NamespacesMustBeReady(t, suite.Client, suite.TimeoutConfig, []string{ns})

		gwNN := types.NamespacedName{Name: "grpcroute-listener-hostname-matching", Namespace: ns}

		_ = kubernetes.GatewayAndRoutesMustBeAccepted(t, suite.Client, suite.TimeoutConfig, suite.ControllerName,
			kubernetes.NewGatewayRef(gwNN, "listener-1"), &v1.GRPCRoute{},
			types.NamespacedName{Namespace: ns, Name: "backend-v1"},
		)
		_ = kubernetes.GatewayAndRoutesMustBeAccepted(t, suite.Client, suite.TimeoutConfig, suite.ControllerName,
			kubernetes.NewGatewayRef(gwNN, "listener-2"), &v1.GRPCRoute{},
			types.NamespacedName{Namespace: ns, Name: "backend-v2"},
		)
		gwAddr := kubernetes.GatewayAndRoutesMustBeAccepted(t, suite.Client, suite.TimeoutConfig, suite.ControllerName,
			kubernetes.NewGatewayRef(gwNN, "listener-3", "listener-4"), &v1.GRPCRoute{},
			types.NamespacedName{Namespace: ns, Name: "backend-v3"},
		)

		testCases := []grpc.ExpectedResponse{{
			EchoRequest: &pb.EchoRequest{},
			RequestMetadata: &grpc.RequestMetadata{
				Authority: "bar.com",
			},
			Backend:   "grpc-infra-backend-v1",
			Namespace: ns,
		}, {
			EchoRequest: &pb.EchoRequest{},
			RequestMetadata: &grpc.RequestMetadata{
				Authority: "foo.bar.com",
			},
			Backend:   "grpc-infra-backend-v2",
			Namespace: ns,
		}, {
			EchoRequest: &pb.EchoRequest{},
			RequestMetadata: &grpc.RequestMetadata{
				Authority: "baz.bar.com",
			},
			Backend:   "grpc-infra-backend-v3",
			Namespace: ns,
		}, {
			EchoRequest: &pb.EchoRequest{},
			RequestMetadata: &grpc.RequestMetadata{
				Authority: "boo.bar.com",
			},
			Backend:   "grpc-infra-backend-v3",
			Namespace: ns,
		}, {
			EchoRequest: &pb.EchoRequest{},
			RequestMetadata: &grpc.RequestMetadata{
				Authority: "multiple.prefixes.bar.com",
			},
			Backend:   "grpc-infra-backend-v3",
			Namespace: ns,
		}, {
			EchoRequest: &pb.EchoRequest{},
			RequestMetadata: &grpc.RequestMetadata{
				Authority: "multiple.prefixes.foo.com",
			},
			Backend:   "grpc-infra-backend-v3",
			Namespace: ns,
		}, {
			EchoRequest: &pb.EchoRequest{},
			RequestMetadata: &grpc.RequestMetadata{
				Authority: "foo.com",
			},
			Response: grpc.Response{Code: codes.Unimplemented},
		}, {
			EchoRequest: &pb.EchoRequest{},
			RequestMetadata: &grpc.RequestMetadata{
				Authority: "no.matching.host",
			},
			Response: grpc.Response{Code: codes.Unimplemented},
		}}

		for i := range testCases {
			// Declare tc here to avoid loop variable
			// reuse issues across parallel tests.
			tc := testCases[i]
			t.Run(tc.GetTestCaseName(i), func(t *testing.T) {
				t.Parallel()
				grpc.MakeRequestAndExpectEventuallyConsistentResponse(t, suite.GRPCClient, suite.TimeoutConfig, gwAddr, tc)
			})
		}
	},
}
