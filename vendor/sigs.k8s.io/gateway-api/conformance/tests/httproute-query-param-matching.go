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
	ConformanceTests = append(ConformanceTests, HTTPRouteQueryParamMatching)
}

var HTTPRouteQueryParamMatching = suite.ConformanceTest{
	ShortName:   "HTTPRouteQueryParamMatching",
	Description: "A single HTTPRoute with query param matching for different backends",
	Manifests:   []string{"tests/httproute-query-param-matching.yaml"},
	Features:    []suite.SupportedFeature{suite.SupportHTTPRouteQueryParamMatching},
	Test: func(t *testing.T, suite *suite.ConformanceTestSuite) {
		var (
			ns      = "gateway-conformance-infra"
			routeNN = types.NamespacedName{Namespace: ns, Name: "query-param-matching"}
			gwNN    = types.NamespacedName{Namespace: ns, Name: "same-namespace"}
			gwAddr  = kubernetes.GatewayAndHTTPRoutesMustBeAccepted(t, suite.Client, suite.TimeoutConfig, suite.ControllerName, kubernetes.NewGatewayRef(gwNN), routeNN)
		)

		testCases := []http.ExpectedResponse{{
			Request:   http.Request{Path: "/?animal=whale"},
			Backend:   "infra-backend-v1",
			Namespace: ns,
		}, {
			Request:   http.Request{Path: "/?animal=dolphin"},
			Backend:   "infra-backend-v2",
			Namespace: ns,
		}, {
			Request:   http.Request{Path: "/?animal=dolphin&color=blue"},
			Backend:   "infra-backend-v3",
			Namespace: ns,
		}, {
			Request:   http.Request{Path: "/?ANIMAL=Whale"},
			Backend:   "infra-backend-v3",
			Namespace: ns,
		}, {
			Request:   http.Request{Path: "/?animal=whale&otherparam=irrelevant"},
			Backend:   "infra-backend-v1",
			Namespace: ns,
		}, {
			Request:   http.Request{Path: "/?animal=dolphin&color=yellow"},
			Backend:   "infra-backend-v2",
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

		for i := range testCases {
			tc := testCases[i]
			t.Run(tc.GetTestCaseName(i), func(t *testing.T) {
				t.Parallel()
				http.MakeRequestAndExpectEventuallyConsistentResponse(t, suite.RoundTripper, suite.TimeoutConfig, gwAddr, tc)
			})
		}
	},
}
