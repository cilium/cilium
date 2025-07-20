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
	ConformanceTests = append(ConformanceTests, HTTPRoutePathMatchOrder)
}

var HTTPRoutePathMatchOrder = suite.ConformanceTest{
	ShortName:   "HTTPRoutePathMatchOrder",
	Description: "An HTTPRoute where there are multiple matches routing to any given backend follows match order precedence",
	Features: []features.FeatureName{
		features.SupportGateway,
		features.SupportHTTPRoute,
	},
	Manifests: []string{"tests/httproute-path-match-order.yaml"},
	Test: func(t *testing.T, suite *suite.ConformanceTestSuite) {
		ns := "gateway-conformance-infra"
		routeNN := types.NamespacedName{Namespace: ns, Name: "path-matching-order"}
		gwNN := types.NamespacedName{Namespace: ns, Name: "same-namespace"}
		gwAddr := kubernetes.GatewayAndHTTPRoutesMustBeAccepted(t, suite.Client, suite.TimeoutConfig, suite.ControllerName, kubernetes.NewGatewayRef(gwNN), routeNN)
		kubernetes.HTTPRouteMustHaveResolvedRefsConditionsTrue(t, suite.Client, suite.TimeoutConfig, routeNN, gwNN)

		testCases := []http.ExpectedResponse{
			{
				Request:   http.Request{Path: "/match/exact/one"},
				Backend:   "infra-backend-v3",
				Namespace: ns,
			}, {
				Request:   http.Request{Path: "/match/exact"},
				Backend:   "infra-backend-v2",
				Namespace: ns,
			}, {
				Request:   http.Request{Path: "/match"},
				Backend:   "infra-backend-v1",
				Namespace: ns,
			}, {
				Request:   http.Request{Path: "/match/prefix/one/any"},
				Backend:   "infra-backend-v2",
				Namespace: ns,
			}, {
				Request:   http.Request{Path: "/match/prefix/any"},
				Backend:   "infra-backend-v1",
				Namespace: ns,
			}, {
				Request:   http.Request{Path: "/match/any"},
				Backend:   "infra-backend-v3",
				Namespace: ns,
			},
		}

		for i := range testCases {
			tc := testCases[i]
			t.Run(tc.GetTestCaseName(i), func(t *testing.T) {
				t.Parallel()
				http.MakeRequestAndExpectEventuallyConsistentResponse(t, suite.RoundTripper, suite.TimeoutConfig, gwAddr, tc)
			})
		}
	},
}
