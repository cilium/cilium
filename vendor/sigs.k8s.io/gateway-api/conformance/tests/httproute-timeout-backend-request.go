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

	"k8s.io/apimachinery/pkg/types"

	"sigs.k8s.io/gateway-api/conformance/utils/http"
	"sigs.k8s.io/gateway-api/conformance/utils/kubernetes"
	"sigs.k8s.io/gateway-api/conformance/utils/suite"
	"sigs.k8s.io/gateway-api/pkg/features"
)

func init() {
	ConformanceTests = append(ConformanceTests, HTTPRouteTimeoutBackendRequest)
}

// Note that here we are only making sure BackendRequest timeouts work individually.
// TODO: once we add retry support to Gateway API (future GEP-1731), add conformance tests to show
// Request and BackendRequest timeouts working together.

var HTTPRouteTimeoutBackendRequest = suite.ConformanceTest{
	ShortName:   "HTTPRouteTimeoutBackendRequest",
	Description: "An HTTPRoute with backend request timeout",
	Manifests:   []string{"tests/httproute-timeout-backend-request.yaml"},
	Features: []features.FeatureName{
		features.SupportGateway,
		features.SupportHTTPRoute,
		features.SupportHTTPRouteBackendTimeout,
	},
	Test: func(t *testing.T, suite *suite.ConformanceTestSuite) {
		ns := "gateway-conformance-infra"
		routeNN := types.NamespacedName{Name: "backend-request-timeout", Namespace: ns}
		gwNN := types.NamespacedName{Name: "same-namespace", Namespace: ns}
		gwAddr := kubernetes.GatewayAndHTTPRoutesMustBeAccepted(t, suite.Client, suite.TimeoutConfig, suite.ControllerName, kubernetes.NewGatewayRef(gwNN), routeNN)
		kubernetes.HTTPRouteMustHaveResolvedRefsConditionsTrue(t, suite.Client, suite.TimeoutConfig, routeNN, gwNN)

		testCases := []http.ExpectedResponse{
			{
				Request:   http.Request{Path: "/backend-timeout"},
				Response:  http.Response{StatusCode: 200},
				Namespace: ns,
			}, {
				Request:   http.Request{Path: "/backend-timeout?delay=1s"},
				Response:  http.Response{StatusCode: 504},
				Namespace: ns,
			}, {
				Request:   http.Request{Path: "/disable-backend-timeout?delay=1s"},
				Response:  http.Response{StatusCode: 200},
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
