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
	ConformanceTests = append(ConformanceTests, MeshTrafficSplit)
}

var MeshTrafficSplit = suite.ConformanceTest{
	ShortName:   "MeshTrafficSplit",
	Description: "A mesh client can send traffic to a Service which is split between two versions",
	Features: []features.FeatureName{
		features.SupportMesh,
		features.SupportHTTPRoute,
	},
	Manifests: []string{"tests/mesh-split.yaml"},
	Test: func(t *testing.T, s *suite.ConformanceTestSuite) {
		client := echo.ConnectToApp(t, s, echo.MeshAppEchoV1)
		cases := []http.ExpectedResponse{
			{
				Request: http.Request{
					Host:   "echo",
					Method: "GET",
					Path:   "/v1",
				},
				Response: http.Response{
					StatusCode: 200,
				},
				Backend: "echo-v1",
			},
			{
				Request: http.Request{
					Host:   "echo",
					Method: "GET",
					Path:   "/v2",
				},
				Response: http.Response{
					StatusCode: 200,
				},
				Backend: "echo-v2",
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
