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
	ConformanceTests = append(ConformanceTests, HTTPRouteRewriteHost)
}

var HTTPRouteRewriteHost = suite.ConformanceTest{
	ShortName:   "HTTPRouteRewriteHost",
	Description: "An HTTPRoute with hostname rewrite filter",
	Manifests:   []string{"tests/httproute-rewrite-host.yaml"},
	Features: []suite.SupportedFeature{
		suite.SupportGateway,
		suite.SupportHTTPRoute,
		suite.SupportHTTPRouteHostRewrite,
	},
	Test: func(t *testing.T, suite *suite.ConformanceTestSuite) {
		ns := "gateway-conformance-infra"
		routeNN := types.NamespacedName{Name: "rewrite-host", Namespace: ns}
		gwNN := types.NamespacedName{Name: "same-namespace", Namespace: ns}
		gwAddr := kubernetes.GatewayAndHTTPRoutesMustBeAccepted(t, suite.Client, suite.TimeoutConfig, suite.ControllerName, kubernetes.NewGatewayRef(gwNN), routeNN)
		kubernetes.HTTPRouteMustHaveResolvedRefsConditionsTrue(t, suite.Client, suite.TimeoutConfig, routeNN, gwNN)

		testCases := []http.ExpectedResponse{
			{
				Request: http.Request{
					Path: "/one",
					Host: "rewrite.example",
				},
				ExpectedRequest: &http.ExpectedRequest{
					Request: http.Request{
						Path: "/one",
						Host: "one.example.org",
					},
				},
				Backend:   "infra-backend-v1",
				Namespace: ns,
			}, {
				Request: http.Request{
					Path: "/two",
					Host: "rewrite.example",
				},
				ExpectedRequest: &http.ExpectedRequest{
					Request: http.Request{
						Path: "/two",
						Host: "example.org",
					},
				},
				Backend:   "infra-backend-v2",
				Namespace: ns,
			}, {
				Request: http.Request{
					Path: "/rewrite-host-and-modify-headers",
					Host: "rewrite.example",
					Headers: map[string]string{
						"X-Header-Remove":     "remove-val",
						"X-Header-Add-Append": "append-val-1",
					},
				},
				ExpectedRequest: &http.ExpectedRequest{
					Request: http.Request{
						Path: "/rewrite-host-and-modify-headers",
						Host: "test.example.org",
						Headers: map[string]string{
							"X-Header-Add":        "header-val-1",
							"X-Header-Add-Append": "append-val-1,header-val-2",
							"X-Header-Set":        "set-overwrites-values",
						},
					},
					AbsentHeaders: []string{"X-Header-Remove"},
				},
				Backend:   "infra-backend-v2",
				Namespace: ns,
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
