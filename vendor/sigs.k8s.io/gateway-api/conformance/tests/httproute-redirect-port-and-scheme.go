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
	"sigs.k8s.io/gateway-api/conformance/utils/roundtripper"
	"sigs.k8s.io/gateway-api/conformance/utils/suite"
	"sigs.k8s.io/gateway-api/conformance/utils/tls"
	"sigs.k8s.io/gateway-api/pkg/features"
)

func init() {
	ConformanceTests = append(ConformanceTests, HTTPRouteRedirectPortAndScheme)
}

var HTTPRouteRedirectPortAndScheme = suite.ConformanceTest{
	ShortName:   "HTTPRouteRedirectPortAndScheme",
	Description: "An HTTPRoute with port and scheme redirect filter",
	Manifests:   []string{"tests/httproute-redirect-port-and-scheme.yaml"},
	Features: []features.FeatureName{
		features.SupportGateway,
		features.SupportHTTPRoute,
		features.SupportHTTPRoutePortRedirect,
		features.SupportGatewayPort8080,
	},
	Test: func(t *testing.T, suite *suite.ConformanceTestSuite) {
		ns := "gateway-conformance-infra"

		gwNN := types.NamespacedName{Name: "same-namespace", Namespace: ns}
		routeNN := types.NamespacedName{Name: "http-route-for-listener-on-port-80", Namespace: ns}
		gwAddr80 := kubernetes.GatewayAndHTTPRoutesMustBeAccepted(t, suite.Client, suite.TimeoutConfig, suite.ControllerName, kubernetes.NewGatewayRef(gwNN), routeNN)
		kubernetes.HTTPRouteMustHaveResolvedRefsConditionsTrue(t, suite.Client, suite.TimeoutConfig, routeNN, gwNN)

		gwNN = types.NamespacedName{Name: "same-namespace-with-http-listener-on-8080", Namespace: ns}
		routeNN = types.NamespacedName{Name: "http-route-for-listener-on-port-8080", Namespace: ns}
		gwAddr8080 := kubernetes.GatewayAndHTTPRoutesMustBeAccepted(t, suite.Client, suite.TimeoutConfig, suite.ControllerName, kubernetes.NewGatewayRef(gwNN), routeNN)
		kubernetes.HTTPRouteMustHaveResolvedRefsConditionsTrue(t, suite.Client, suite.TimeoutConfig, routeNN, gwNN)

		gwNN = types.NamespacedName{Name: "same-namespace-with-https-listener", Namespace: ns}
		routeNN = types.NamespacedName{Name: "http-route-for-listener-on-port-443", Namespace: ns}
		gwAddr443 := kubernetes.GatewayAndHTTPRoutesMustBeAccepted(t, suite.Client, suite.TimeoutConfig, suite.ControllerName, kubernetes.NewGatewayRef(gwNN), routeNN)
		kubernetes.HTTPRouteMustHaveResolvedRefsConditionsTrue(t, suite.Client, suite.TimeoutConfig, routeNN, gwNN)

		certNN := types.NamespacedName{Name: "tls-validity-checks-certificate", Namespace: ns}
		cPem, keyPem, err := GetTLSSecret(suite.Client, certNN)
		if err != nil {
			t.Fatalf("unexpected error finding TLS secret: %v", err)
		}

		// NOTE: In all the test cases, a missing value of expected Port within
		//   RedirectRequest implies that it is still valid and acceptable for a
		//   port to be specified in the redirect if it corresponds to the scheme
		//   (80 and 443).

		////////////////////////////////////////////////////////////////////////////
		// Test cases that use http-route-for-listener-on-port-80
		////////////////////////////////////////////////////////////////////////////

		testCases := []http.ExpectedResponse{
			{
				Request: http.Request{
					Path:             "/scheme-nil-and-port-nil",
					UnfollowRedirect: true,
				},
				Response: http.Response{StatusCode: 302},
				RedirectRequest: &roundtripper.RedirectRequest{
					Scheme: "http",
					Host:   "example.org",
				},
				Namespace: ns,
			},
			{
				Request: http.Request{
					Path:             "/scheme-nil-and-port-80",
					UnfollowRedirect: true,
				},
				Response: http.Response{StatusCode: 302},
				RedirectRequest: &roundtripper.RedirectRequest{
					Scheme: "http",
					Host:   "example.org",
				},
				Namespace: ns,
			},
			{
				Request: http.Request{
					Path:             "/scheme-nil-and-port-8080",
					UnfollowRedirect: true,
				},
				Response: http.Response{StatusCode: 302},
				RedirectRequest: &roundtripper.RedirectRequest{
					Scheme: "http",
					Port:   "8080",
					Host:   "example.org",
				},
				Namespace: ns,
			},
			{
				Request: http.Request{
					Path:             "/scheme-https-and-port-nil",
					UnfollowRedirect: true,
				},
				Response: http.Response{StatusCode: 302},
				RedirectRequest: &roundtripper.RedirectRequest{
					Scheme: "https",
					Host:   "example.org",
				},
				Namespace: ns,
			},
			{
				Request: http.Request{
					Path:             "/scheme-https-and-port-443",
					UnfollowRedirect: true,
				},
				Response: http.Response{StatusCode: 302},
				RedirectRequest: &roundtripper.RedirectRequest{
					Scheme: "https",
					Host:   "example.org",
				},
				Namespace: ns,
			},
			{
				Request: http.Request{
					Path:             "/scheme-https-and-port-8443",
					UnfollowRedirect: true,
				},
				Response: http.Response{StatusCode: 302},
				RedirectRequest: &roundtripper.RedirectRequest{
					Scheme: "https",
					Port:   "8443",
					Host:   "example.org",
				},
				Namespace: ns,
			},
		}

		for i := range testCases {
			tc := testCases[i]
			t.Run("http-listener-on-80/"+tc.GetTestCaseName(i), func(t *testing.T) {
				t.Parallel()
				http.MakeRequestAndExpectEventuallyConsistentResponse(t, suite.RoundTripper, suite.TimeoutConfig, gwAddr80, tc)
			})
		}

		////////////////////////////////////////////////////////////////////////////
		// Test cases that use same-namespace-with-http-listener-on-8080
		////////////////////////////////////////////////////////////////////////////

		testCases = []http.ExpectedResponse{
			{
				Request: http.Request{
					Path:             "/scheme-nil-and-port-nil",
					UnfollowRedirect: true,
				},
				Response: http.Response{StatusCode: 302},
				RedirectRequest: &roundtripper.RedirectRequest{
					Scheme: "http",
					Port:   "8080",
					Host:   "example.org",
				},
				Namespace: ns,
			},
			{
				Request: http.Request{
					Path:             "/scheme-nil-and-port-80",
					UnfollowRedirect: true,
				},
				Response: http.Response{StatusCode: 302},
				RedirectRequest: &roundtripper.RedirectRequest{
					Scheme: "http",
					Host:   "example.org",
				},
				Namespace: ns,
			},
			{
				Request: http.Request{
					Path:             "/scheme-https-and-port-nil",
					UnfollowRedirect: true,
				},
				Response: http.Response{StatusCode: 302},
				RedirectRequest: &roundtripper.RedirectRequest{
					Scheme: "https",
					Host:   "example.org",
				},
				Namespace: ns,
			},
		}

		for i := range testCases {
			tc := testCases[i]
			t.Run("http-listener-on-8080/"+tc.GetTestCaseName(i), func(t *testing.T) {
				t.Parallel()
				http.MakeRequestAndExpectEventuallyConsistentResponse(t, suite.RoundTripper, suite.TimeoutConfig, gwAddr8080, tc)
			})
		}

		////////////////////////////////////////////////////////////////////////////
		// Test cases that use http-route-for-listener-on-port-443
		////////////////////////////////////////////////////////////////////////////

		testCases = []http.ExpectedResponse{
			{
				Request: http.Request{
					Host:             "example.org",
					Path:             "/scheme-nil-and-port-nil",
					UnfollowRedirect: true,
				},
				Response: http.Response{StatusCode: 302},
				RedirectRequest: &roundtripper.RedirectRequest{
					Scheme: "https",
					Host:   "example.org",
				},
				Namespace: ns,
			},
			{
				Request: http.Request{
					Host:             "example.org",
					Path:             "/scheme-nil-and-port-443",
					UnfollowRedirect: true,
				},
				Response: http.Response{StatusCode: 302},
				RedirectRequest: &roundtripper.RedirectRequest{
					Scheme: "https",
					Host:   "example.org",
				},
				Namespace: ns,
			},
			{
				Request: http.Request{
					Host:             "example.org",
					Path:             "/scheme-nil-and-port-8443",
					UnfollowRedirect: true,
				},
				Response: http.Response{StatusCode: 302},
				RedirectRequest: &roundtripper.RedirectRequest{
					Scheme: "https",
					Port:   "8443",
					Host:   "example.org",
				},
				Namespace: ns,
			},
			{
				Request: http.Request{
					Host:             "example.org",
					Path:             "/scheme-http-and-port-nil",
					UnfollowRedirect: true,
				},
				Response: http.Response{StatusCode: 302},
				RedirectRequest: &roundtripper.RedirectRequest{
					Scheme: "http",
					Host:   "example.org",
				},
				Namespace: ns,
			},
			{
				Request: http.Request{
					Host:             "example.org",
					Path:             "/scheme-http-and-port-80",
					UnfollowRedirect: true,
				},
				Response: http.Response{StatusCode: 302},
				RedirectRequest: &roundtripper.RedirectRequest{
					Scheme: "http",
					Host:   "example.org",
				},
				Namespace: ns,
			},
			{
				Request: http.Request{
					Host:             "example.org",
					Path:             "/scheme-http-and-port-8080",
					UnfollowRedirect: true,
				},
				Response: http.Response{StatusCode: 302},
				RedirectRequest: &roundtripper.RedirectRequest{
					Scheme: "http",
					Port:   "8080",
					Host:   "example.org",
				},
				Namespace: ns,
			},
		}

		for i := range testCases {
			tc := testCases[i]
			t.Run("https-listener-on-443/"+tc.GetTestCaseName(i), func(t *testing.T) {
				t.Parallel()
				tls.MakeTLSRequestAndExpectEventuallyConsistentResponse(t, suite.RoundTripper, suite.TimeoutConfig, gwAddr443, cPem, keyPem, "example.org", tc)
			})
		}
	},
}
