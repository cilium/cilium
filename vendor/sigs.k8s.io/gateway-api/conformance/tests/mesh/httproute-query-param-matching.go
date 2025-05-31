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
	MeshConformanceTests = append(MeshConformanceTests, MeshHTTPRouteQueryParamMatching)
}

var MeshHTTPRouteQueryParamMatching = suite.ConformanceTest{
	ShortName:   "MeshHTTPRouteQueryParamMatching",
	Description: "A single HTTPRoute with query param matching for different backends",
	Manifests:   []string{"tests/mesh/httproute-query-param-matching.yaml"},
	Features: []features.FeatureName{
		features.SupportMesh,
		features.SupportHTTPRoute,
		features.SupportMeshHTTPRouteQueryParamMatching,
	},
	Test: func(t *testing.T, s *suite.ConformanceTestSuite) {
		ns := "gateway-conformance-mesh"
		client := echo.ConnectToApp(t, s, echo.MeshAppEchoV1)

		testCases := []http.ExpectedResponse{{
			Request:   http.Request{Path: "/?animal=whale"},
			Backend:   "echo-v1",
			Namespace: ns,
		}, {
			Request:   http.Request{Path: "/?animal=dolphin"},
			Backend:   "echo-v2",
			Namespace: ns,
		}, {
			Request:   http.Request{Path: "/?animal=whale&otherparam=irrelevant"},
			Backend:   "echo-v1",
			Namespace: ns,
		}, {
			Request:   http.Request{Path: "/?animal=dolphin&color=yellow"},
			Backend:   "echo-v2",
			Namespace: ns,
		}, {
			Request:  http.Request{Path: "/?color=blue"},
			Response: http.Response{StatusCode: 404},
		}, {
			Request:  http.Request{Path: "/?animal=dog"},
			Response: http.Response{StatusCode: 404},
		}, {
			Request:  http.Request{Path: "/?animal=whaledolphin"},
			Response: http.Response{StatusCode: 404},
		}, {
			Request:  http.Request{Path: "/"},
			Response: http.Response{StatusCode: 404},
		}}

		// Combinations of query param matching with other core matches.
		testCases = append(testCases, []http.ExpectedResponse{
			{
				Request:   http.Request{Path: "/path1?animal=whale"},
				Backend:   "echo-v1",
				Namespace: ns,
			},
			{
				Request:   http.Request{Headers: map[string]string{"version": "one"}, Path: "/?animal=whale"},
				Backend:   "echo-v2",
				Namespace: ns,
			},
		}...)

		// Ensure that combinations of matches which are OR'd together match
		// even if only one of them is used in the request.
		testCases = append(testCases, []http.ExpectedResponse{
			{
				Request:   http.Request{Path: "/path3?animal=shark"},
				Backend:   "echo-v1",
				Namespace: ns,
			},
			{
				Request:   http.Request{Headers: map[string]string{"version": "three"}, Path: "/path4?animal=kraken"},
				Backend:   "echo-v1",
				Namespace: ns,
			},
		}...)

		// Ensure that combinations of match types which are ANDed together do not match
		// when only a subset of match types is used in the request.
		testCases = append(testCases, []http.ExpectedResponse{
			{
				Request:  http.Request{Path: "/?animal=shark"},
				Response: http.Response{StatusCode: 404},
			},
			{
				Request:  http.Request{Path: "/path4?animal=kraken"},
				Response: http.Response{StatusCode: 404},
			},
		}...)

		// For requests that satisfy multiple matches, ensure precedence order
		// defined by the Gateway API spec is maintained.
		testCases = append(testCases, []http.ExpectedResponse{
			{
				Request:   http.Request{Path: "/path5?animal=hydra"},
				Backend:   "echo-v1",
				Namespace: ns,
			},
		}...)

		for i := range testCases {
			tc := testCases[i]
			t.Run(tc.GetTestCaseName(i), func(t *testing.T) {
				t.Parallel()
				client.MakeRequestAndExpectEventuallyConsistentResponse(t, tc, s.TimeoutConfig)
			})
		}
	},
}
