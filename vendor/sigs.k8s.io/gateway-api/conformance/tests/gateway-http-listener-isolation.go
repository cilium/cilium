/*
Copyright 2024 The Kubernetes Authors.

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
	ConformanceTests = append(ConformanceTests, GatewayHTTPListenerIsolation)
}

var GatewayHTTPListenerIsolation = suite.ConformanceTest{
	ShortName:   "GatewayHTTPListenerIsolation",
	Description: "Listener isolation for HTTP listeners with multiple listeners and HTTPRoutes",
	Features: []features.FeatureName{
		features.SupportGateway,
		features.SupportGatewayHTTPListenerIsolation,
		features.SupportHTTPRoute,
	},
	Manifests: []string{
		"tests/gateway-http-listener-isolation.yaml",
		"tests/gateway-http-listener-isolation-with-hostname-intersection.yaml",
	},
	Test: func(t *testing.T, suite *suite.ConformanceTestSuite) {
		ns := "gateway-conformance-infra"

		kubernetes.NamespacesMustBeReady(t, suite.Client, suite.TimeoutConfig, []string{ns})

		testCases := []http.ExpectedResponse{
			// Requests to the empty-hostname listener
			{
				Request:   http.Request{Host: "bar.com", Path: "/empty-hostname"},
				Backend:   "infra-backend-v1",
				Namespace: ns,
			},
			{
				Request:  http.Request{Host: "bar.com", Path: "/wildcard-example-com"},
				Response: http.Response{StatusCode: 404},
			},
			{
				Request:  http.Request{Host: "bar.com", Path: "/wildcard-foo-example-com"},
				Response: http.Response{StatusCode: 404},
			},
			{
				Request:  http.Request{Host: "bar.com", Path: "/abc-foo-example-com"},
				Response: http.Response{StatusCode: 404},
			},
			// Requests to the wildcard-example-com listener
			{
				Request:  http.Request{Host: "bar.example.com", Path: "/empty-hostname"},
				Response: http.Response{StatusCode: 404},
			},
			{
				Request:   http.Request{Host: "bar.example.com", Path: "/wildcard-example-com"},
				Backend:   "infra-backend-v1",
				Namespace: ns,
			},
			{
				Request:  http.Request{Host: "bar.example.com", Path: "/wildcard-foo-example-com"},
				Response: http.Response{StatusCode: 404},
			},
			{
				Request:  http.Request{Host: "bar.example.com", Path: "/abc-foo-example-com"},
				Response: http.Response{StatusCode: 404},
			},
			// Requests to the foo-wildcard-example-com listener
			{
				Request:  http.Request{Host: "bar.foo.example.com", Path: "/empty-hostname"},
				Response: http.Response{StatusCode: 404},
			},
			{
				Request:  http.Request{Host: "bar.foo.example.com", Path: "/wildcard-example-com"},
				Response: http.Response{StatusCode: 404},
			},
			{
				Request:   http.Request{Host: "bar.foo.example.com", Path: "/wildcard-foo-example-com"},
				Backend:   "infra-backend-v1",
				Namespace: ns,
			},
			{
				Request:  http.Request{Host: "bar.foo.example.com", Path: "/abc-foo-example-com"},
				Response: http.Response{StatusCode: 404},
			},
			// Requests to the abc-foo-example-com listener
			{
				Request:  http.Request{Host: "abc.foo.example.com", Path: "/empty-hostname"},
				Response: http.Response{StatusCode: 404},
			},
			{
				Request:  http.Request{Host: "abc.foo.example.com", Path: "/wildcard-example-com"},
				Response: http.Response{StatusCode: 404},
			},
			{
				Request:   http.Request{Host: "abc.foo.example.com", Path: "/wildcard-foo-example-com"},
				Response:  http.Response{StatusCode: 404},
				Namespace: ns,
			},
			{
				Request:   http.Request{Host: "abc.foo.example.com", Path: "/abc-foo-example-com"},
				Backend:   "infra-backend-v1",
				Namespace: ns,
			},
		}

		t.Run("hostnames are configured only in listeners", func(t *testing.T) {
			gwNN := types.NamespacedName{Name: "http-listener-isolation", Namespace: ns}
			routes := []types.NamespacedName{
				{Namespace: ns, Name: "attaches-to-empty-hostname"},
				{Namespace: ns, Name: "attaches-to-wildcard-example-com"},
				{Namespace: ns, Name: "attaches-to-wildcard-foo-example-com"},
				{Namespace: ns, Name: "attaches-to-abc-foo-example-com"},
			}

			gwAddr := kubernetes.GatewayAndHTTPRoutesMustBeAccepted(t, suite.Client, suite.TimeoutConfig, suite.ControllerName, kubernetes.NewGatewayRef(gwNN), routes...)
			for _, routeNN := range routes {
				kubernetes.HTTPRouteMustHaveResolvedRefsConditionsTrue(t, suite.Client, suite.TimeoutConfig, routeNN, gwNN)
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
		})

		t.Run("intersecting hostnames are configured in listeners and HTTPRoutes", func(t *testing.T) {
			gwNN := types.NamespacedName{Name: "http-listener-isolation-with-hostname-intersection", Namespace: ns}
			routes := []types.NamespacedName{
				{Namespace: ns, Name: "attaches-to-empty-hostname-with-hostname-intersection"},
				{Namespace: ns, Name: "attaches-to-wildcard-example-com-with-hostname-intersection"},
				{Namespace: ns, Name: "attaches-to-wildcard-foo-example-com-with-hostname-intersection"},
				{Namespace: ns, Name: "attaches-to-abc-foo-example-com-with-hostname-intersection"},
			}

			gwAddr := kubernetes.GatewayAndHTTPRoutesMustBeAccepted(t, suite.Client, suite.TimeoutConfig, suite.ControllerName, kubernetes.NewGatewayRef(gwNN), routes...)
			for _, routeNN := range routes {
				kubernetes.HTTPRouteMustHaveResolvedRefsConditionsTrue(t, suite.Client, suite.TimeoutConfig, routeNN, gwNN)
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
		})
	},
}
