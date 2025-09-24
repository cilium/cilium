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
	"testing"

	"sigs.k8s.io/gateway-api/conformance/utils/echo"
	"sigs.k8s.io/gateway-api/conformance/utils/http"
	"sigs.k8s.io/gateway-api/conformance/utils/suite"
	"sigs.k8s.io/gateway-api/pkg/features"
)

func init() {
	MeshConformanceTests = append(MeshConformanceTests, MeshHTTPRouteNamedRule)
}

var MeshHTTPRouteNamedRule = suite.ConformanceTest{
	ShortName:   "MeshHTTPRouteNamedRule",
	Description: "An HTTPRoute with a named HTTPRouteRule",
	Manifests:   []string{"tests/mesh/httproute-named-rule.yaml"},
	Features: []features.FeatureName{
		features.SupportMesh,
		features.SupportHTTPRoute,
		features.SupportMeshHTTPRouteNamedRouteRule,
	},
	Provisional: true,
	Test: func(t *testing.T, suite *suite.ConformanceTestSuite) {
		ns := "gateway-conformance-mesh"
		client := echo.ConnectToApp(t, suite, echo.MeshAppEchoV1)

		testCases := []http.ExpectedResponse{
			{
				Request:         http.Request{Path: "/named"},
				ExpectedRequest: &http.ExpectedRequest{Request: http.Request{Path: "/named"}},
				Backend:         "echo-v1",
				Namespace:       ns,
			}, {
				Request:         http.Request{Path: "/unnamed"},
				ExpectedRequest: &http.ExpectedRequest{Request: http.Request{Path: "/named"}},
				Backend:         "echo-v2",
				Namespace:       ns,
			},
		}

		for i := range testCases {
			tc := testCases[i]
			t.Run(tc.GetTestCaseName(i), func(t *testing.T) {
				t.Parallel()
				client.MakeRequestAndExpectEventuallyConsistentResponse(t, tc, suite.TimeoutConfig)
			})
		}
	},
}
