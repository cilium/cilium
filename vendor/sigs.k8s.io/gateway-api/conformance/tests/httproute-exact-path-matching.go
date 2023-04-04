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

package tests

import (
	"testing"

	"k8s.io/apimachinery/pkg/types"

	"sigs.k8s.io/gateway-api/conformance/utils/http"
	"sigs.k8s.io/gateway-api/conformance/utils/kubernetes"
	"sigs.k8s.io/gateway-api/conformance/utils/suite"
)

func init() {
	ConformanceTests = append(ConformanceTests, HTTPExactPathMatching)
}

var HTTPExactPathMatching = suite.ConformanceTest{
	ShortName:   "HTTPExactPathMatching",
	Description: "A single HTTPRoute with exact path matching for different backends",
	Manifests:   []string{"tests/httproute-exact-path-matching.yaml"},
	Test: func(t *testing.T, suite *suite.ConformanceTestSuite) {
		ns := "gateway-conformance-infra"
		routeNN := types.NamespacedName{Name: "exact-matching", Namespace: ns}
		gwNN := types.NamespacedName{Name: "same-namespace", Namespace: ns}
		gwAddr := kubernetes.GatewayAndHTTPRoutesMustBeAccepted(t, suite.Client, suite.TimeoutConfig, suite.ControllerName, kubernetes.NewGatewayRef(gwNN), routeNN)

		testCases := []http.ExpectedResponse{
			{
				Request:   http.Request{Path: "/one"},
				Backend:   "infra-backend-v1",
				Namespace: ns,
			}, {
				Request:   http.Request{Path: "/two"},
				Backend:   "infra-backend-v2",
				Namespace: ns,
			}, {
				Request:  http.Request{Path: "/"},
				Response: http.Response{StatusCode: 404},
			}, {
				Request:  http.Request{Path: "/one/example"},
				Response: http.Response{StatusCode: 404},
			}, {
				Request:  http.Request{Path: "/two/"},
				Response: http.Response{StatusCode: 404},
			},
		}

		for i := range testCases {
			// Declare tc here to avoid loop variable
			// reuse issues across parallel tests.
			tc := testCases[i]
			t.Run(tc.GetTestCaseName(i), func(t *testing.T) {
				t.Parallel()
				http.MakeRequestAndExpectEventuallyConsistentResponse(t, suite.RoundTripper, suite.TimeoutConfig, gwAddr, tc)
			})
		}
	},
}
