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
	ConformanceTests = append(ConformanceTests, HTTPRouteMatchingAcrossRoutes)
}

var HTTPRouteMatchingAcrossRoutes = suite.ConformanceTest{
	ShortName:   "HTTPRouteMatchingAcrossRoutes",
	Description: "Two HTTPRoutes with path matching for different backends",
	Features: []suite.SupportedFeature{
		suite.SupportGateway,
		suite.SupportHTTPRoute,
	},
	Manifests: []string{"tests/httproute-matching-across-routes.yaml"},
	Test: func(t *testing.T, suite *suite.ConformanceTestSuite) {
		ns := "gateway-conformance-infra"
		routeNN1 := types.NamespacedName{Name: "matching-part1", Namespace: ns}
		routeNN2 := types.NamespacedName{Name: "matching-part2", Namespace: ns}
		gwNN := types.NamespacedName{Name: "same-namespace", Namespace: ns}
		gwAddr := kubernetes.GatewayAndHTTPRoutesMustBeAccepted(t, suite.Client, suite.TimeoutConfig, suite.ControllerName, kubernetes.NewGatewayRef(gwNN), routeNN1, routeNN2)
		kubernetes.HTTPRouteMustHaveResolvedRefsConditionsTrue(t, suite.Client, suite.TimeoutConfig, routeNN1, gwNN)
		kubernetes.HTTPRouteMustHaveResolvedRefsConditionsTrue(t, suite.Client, suite.TimeoutConfig, routeNN2, gwNN)

		testCases := []http.ExpectedResponse{{
			Request: http.Request{
				Host: "example.com",
				Path: "/",
			},
			Backend:   "infra-backend-v1",
			Namespace: ns,
		}, {
			Request: http.Request{
				Host: "example.com",
				Path: "/example",
			},
			Backend:   "infra-backend-v1",
			Namespace: ns,
		}, {
			Request: http.Request{
				Host: "example.net",
				Path: "/example",
			},
			Backend:   "infra-backend-v1",
			Namespace: ns,
		}, {
			Request: http.Request{
				Host:    "example.com",
				Path:    "/example",
				Headers: map[string]string{"Version": "one"},
			},
			Backend:   "infra-backend-v1",
			Namespace: ns,
		}, {
			Request: http.Request{
				Host: "example.com",
				Path: "/v2",
			},
			Backend:   "infra-backend-v2",
			Namespace: ns,
		}, {
			Request: http.Request{
				// v2 matches are limited to example.com
				Host: "example.net",
				Path: "/v2",
			},
			Backend:   "infra-backend-v1",
			Namespace: ns,
		}, {
			Request: http.Request{
				Host: "example.com",
				Path: "/v2/example",
			},
			Backend:   "infra-backend-v2",
			Namespace: ns,
		}, {
			Request: http.Request{
				Host:    "example.com",
				Path:    "/",
				Headers: map[string]string{"Version": "two"},
			},
			Backend:   "infra-backend-v2",
			Namespace: ns,
		}}

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
