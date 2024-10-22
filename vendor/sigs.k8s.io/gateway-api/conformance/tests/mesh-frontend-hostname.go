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
	ConformanceTests = append(ConformanceTests, MeshFrontendHostname)
}

var MeshFrontendHostname = suite.ConformanceTest{
	ShortName:   "MeshFrontendHostname",
	Description: "Mesh parentRef matches Service IP (not Host)",
	Features: []features.FeatureName{
		features.SupportMesh,
		features.SupportMeshClusterIPMatching,
		features.SupportHTTPRoute,
		features.SupportHTTPRouteResponseHeaderModification,
	},
	Manifests: []string{"tests/mesh-frontend.yaml"},
	Test: func(t *testing.T, s *suite.ConformanceTestSuite) {
		client := echo.ConnectToApp(t, s, echo.MeshAppEchoV1)
		cases := []http.ExpectedResponse{
			{
				TestCaseName: "Send to service with wrong hostname",
				Request: http.Request{
					Host: "echo-v2",
					Headers: map[string]string{
						"Host": "echo-v1",
					},
					Method: "GET",
				},
				Response: http.Response{
					StatusCode: 200,
					// Make sure the route actually did something
					Headers: map[string]string{
						"X-Header-Set": "set",
					},
				},
				Backend: "echo-v2",
			},
			{
				TestCaseName: "Send to other service with matching hostname",
				Request: http.Request{
					Host: "echo-v1",
					Headers: map[string]string{
						"Host": "echo-v2",
					},
					Method: "GET",
				},
				Response: http.Response{
					StatusCode:    200,
					AbsentHeaders: []string{"X-Header-Set"},
				},
				Backend: "echo-v1",
			},
		}
		for i := range cases {
			// Declare tc here to avoid loop variable
			// reuse issues across parallel tests.
			tc := cases[i]
			t.Run(tc.GetTestCaseName(i), func(t *testing.T) {
				client.MakeRequestAndExpectEventuallyConsistentResponse(t, tc, s.TimeoutConfig)
			})
		}
	},
}
