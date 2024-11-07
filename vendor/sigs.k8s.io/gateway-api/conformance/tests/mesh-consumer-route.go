/*
Copyright 2023 The Kubernetes Authors.

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

	"sigs.k8s.io/gateway-api/conformance/utils/echo"
	"sigs.k8s.io/gateway-api/conformance/utils/http"
	"sigs.k8s.io/gateway-api/conformance/utils/suite"
	"sigs.k8s.io/gateway-api/pkg/features"
)

func init() {
	ConformanceTests = append(ConformanceTests, MeshConsumerRoute)
}

var MeshConsumerRoute = suite.ConformanceTest{
	ShortName:   "MeshConsumerRoute",
	Description: "An HTTPRoute in a namespace other than its parentRef's namespace only affects requests from the route's namespace",
	Features: []features.FeatureName{
		features.SupportMesh,
		features.SupportMeshConsumerRoute,
		features.SupportHTTPRoute,
		features.SupportHTTPRouteResponseHeaderModification,
	},
	Manifests: []string{"tests/mesh-consumer-route.yaml"},
	Test: func(t *testing.T, s *suite.ConformanceTestSuite) {
		consumerClient := echo.ConnectToAppInNamespace(t, s, echo.MeshAppEchoV1, "gateway-conformance-mesh-consumer")
		consumerCases := []http.ExpectedResponse{
			{
				TestCaseName: "request from consumer route's namespace modified by HTTPRoute",
				Request: http.Request{
					Host:   "echo-v1.gateway-conformance-mesh",
					Method: "GET",
					Path:   "/",
				},
				Response: http.Response{
					StatusCode: 200,
					Headers: map[string]string{
						"X-Header-Set": "set",
					},
				},
				Backend: "echo-v1",
			},
		}
		producerClient := echo.ConnectToAppInNamespace(t, s, echo.MeshAppEchoV1, "gateway-conformance-mesh")
		producerCases := []http.ExpectedResponse{
			{
				TestCaseName: "request not from consumer route's namespace not modified by HTTPRoute",
				Request: http.Request{
					Host:   "echo-v1.gateway-conformance-mesh",
					Method: "GET",
					Path:   "/",
				},
				Response: http.Response{
					StatusCode:    200,
					AbsentHeaders: []string{"X-Header-Set"},
				},
				Backend: "echo-v1",
			},
		}
		for i, tc := range consumerCases {
			t.Run(tc.GetTestCaseName(i), func(t *testing.T) {
				consumerClient.MakeRequestAndExpectEventuallyConsistentResponse(t, tc, s.TimeoutConfig)
			})
		}
		for i, tc := range producerCases {
			t.Run(tc.GetTestCaseName(i), func(t *testing.T) {
				producerClient.MakeRequestAndExpectEventuallyConsistentResponse(t, tc, s.TimeoutConfig)
			})
		}
	},
}
