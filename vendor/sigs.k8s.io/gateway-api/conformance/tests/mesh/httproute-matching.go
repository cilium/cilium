/*
Copyright 2022 The Kubernetes Authors.

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
	MeshConformanceTests = append(MeshConformanceTests, MeshHTTPRouteMatching)
}

var MeshHTTPRouteMatching = suite.ConformanceTest{
	ShortName:   "MeshHTTPRouteMatching",
	Description: "A single HTTPRoute with path and header matching for different backends",
	Features: []features.FeatureName{
		features.SupportMesh,
		features.SupportHTTPRoute,
	},
	Manifests: []string{"tests/mesh/httproute-matching.yaml"},
	Test: func(t *testing.T, s *suite.ConformanceTestSuite) {
		ns := "gateway-conformance-mesh"
		client := echo.ConnectToApp(t, s, echo.MeshAppEchoV1)

		testCases := []http.ExpectedResponse{{
			Request:   http.Request{Path: "/"},
			Backend:   "echo-v1",
			Namespace: ns,
		}, {
			Request:   http.Request{Path: "/example"},
			Backend:   "echo-v1",
			Namespace: ns,
		}, {
			Request:   http.Request{Path: "/", Headers: map[string]string{"Version": "one"}},
			Backend:   "echo-v1",
			Namespace: ns,
		}, {
			Request:   http.Request{Path: "/v2"},
			Backend:   "echo-v2",
			Namespace: ns,
		}, {
			Request:   http.Request{Path: "/v2/example"},
			Backend:   "echo-v2",
			Namespace: ns,
		}, {
			Request:   http.Request{Path: "/", Headers: map[string]string{"Version": "two"}},
			Backend:   "echo-v2",
			Namespace: ns,
		}, {
			Request:   http.Request{Path: "/v2/"},
			Backend:   "echo-v2",
			Namespace: ns,
		}, {
			// Not a path segment prefix so should not match /v2.
			Request:   http.Request{Path: "/v2example"},
			Backend:   "echo-v1",
			Namespace: ns,
		}, {
			Request:   http.Request{Path: "/foo/v2/example"},
			Backend:   "echo-v1",
			Namespace: ns,
		}}

		for i := range testCases {
			// Declare tc here to avoid loop variable
			// reuse issues across parallel tests.
			tc := testCases[i]
			t.Run(tc.GetTestCaseName(i), func(t *testing.T) {
				t.Parallel()
				client.MakeRequestAndExpectEventuallyConsistentResponse(t, tc, s.TimeoutConfig)
			})
		}
	},
}
