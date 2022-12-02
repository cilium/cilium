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
	ConformanceTests = append(ConformanceTests, HTTPRouteListenerHostnameMatching)
}

var HTTPRouteListenerHostnameMatching = suite.ConformanceTest{
	ShortName:   "HTTPRouteListenerHostnameMatching",
	Description: "Multiple HTTP listeners with the same port and different hostnames, each with a different HTTPRoute",
	Manifests:   []string{"tests/httproute-listener-hostname-matching.yaml"},
	Test: func(t *testing.T, suite *suite.ConformanceTestSuite) {
		ns := "gateway-conformance-infra"

		// This test creates an additional Gateway in the gateway-conformance-infra
		// namespace so we have to wait for it to be ready.
		kubernetes.NamespacesMustBeAccepted(t, suite.Client, suite.TimeoutConfig, []string{ns})

		gwNN := types.NamespacedName{Name: "httproute-listener-hostname-matching", Namespace: ns}

		_ = kubernetes.GatewayAndHTTPRoutesMustBeAccepted(t, suite.Client, suite.TimeoutConfig, suite.ControllerName, kubernetes.NewGatewayRef(gwNN, "listener-1"),
			types.NamespacedName{Namespace: ns, Name: "backend-v1"},
		)
		_ = kubernetes.GatewayAndHTTPRoutesMustBeAccepted(t, suite.Client, suite.TimeoutConfig, suite.ControllerName, kubernetes.NewGatewayRef(gwNN, "listener-2"),
			types.NamespacedName{Namespace: ns, Name: "backend-v2"},
		)
		gwAddr := kubernetes.GatewayAndHTTPRoutesMustBeAccepted(t, suite.Client, suite.TimeoutConfig, suite.ControllerName, kubernetes.NewGatewayRef(gwNN, "listener-3", "listener-4"),
			types.NamespacedName{Namespace: ns, Name: "backend-v3"},
		)

		testCases := []http.ExpectedResponse{{
			Request:   http.Request{Host: "bar.com", Path: "/"},
			Backend:   "infra-backend-v1",
			Namespace: ns,
		}, {
			Request:   http.Request{Host: "foo.bar.com", Path: "/"},
			Backend:   "infra-backend-v2",
			Namespace: ns,
		}, {
			Request:   http.Request{Host: "baz.bar.com", Path: "/"},
			Backend:   "infra-backend-v3",
			Namespace: ns,
		}, {
			Request:   http.Request{Host: "boo.bar.com", Path: "/"},
			Backend:   "infra-backend-v3",
			Namespace: ns,
		}, {
			Request:   http.Request{Host: "multiple.prefixes.bar.com", Path: "/"},
			Backend:   "infra-backend-v3",
			Namespace: ns,
		}, {
			Request:   http.Request{Host: "multiple.prefixes.foo.com", Path: "/"},
			Backend:   "infra-backend-v3",
			Namespace: ns,
		}, {
			Request:  http.Request{Host: "foo.com", Path: "/"},
			Response: http.Response{StatusCode: 404},
		}, {
			Request:  http.Request{Host: "no.matching.host", Path: "/"},
			Response: http.Response{StatusCode: 404},
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
