/*
Copyright The Kubernetes Authors.

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
	"sigs.k8s.io/gateway-api/conformance/utils/tls"
	"sigs.k8s.io/gateway-api/pkg/features"
)

func init() {
	ConformanceTests = append(ConformanceTests, TLSRouteHostnameIntersection)
}

var TLSRouteHostnameIntersection = suite.ConformanceTest{
	ShortName:   "TLSRouteHostnameIntersection",
	Description: "TLSRoutes should attach to listeners only if they have intersecting hostnames, and should accept requests only for the intersecting hostnames",
	Features: []features.FeatureName{
		features.SupportGateway,
		features.SupportTLSRoute,
	},
	Manifests: []string{"tests/tlsroute-hostname-intersection.yaml"},
	Test: func(t *testing.T, suite *suite.ConformanceTestSuite) {
		ns := "gateway-conformance-infra"
		certNN := types.NamespacedName{Name: "tls-checks-certificate", Namespace: ns}

		// This test creates an additional Gateway in the gateway-conformance-infra
		// namespace so we have to wait for it to be ready.
		kubernetes.NamespacesMustBeReady(t, suite.Client, suite.TimeoutConfig, []string{ns})

		serverCertPem, _, err := GetTLSSecret(suite.Client, certNN)
		if err != nil {
			t.Fatalf("unexpected error finding TLS secret: %v", err)
		}

		t.Run("TLSRoutes intersect with exact listener hostname", func(t *testing.T) {
			routeNN := types.NamespacedName{Namespace: ns, Name: "tlsroute-more-specific-wc-hostname-x-1"}
			gwNN := types.NamespacedName{Name: "gw-tlsroute-exact-hostname-x-1", Namespace: ns}
			gwAddr, _ := kubernetes.GatewayAndTLSRoutesMustBeAccepted(t, suite.Client, suite.TimeoutConfig, suite.ControllerName, kubernetes.NewGatewayRef(gwNN), routeNN)

			kubernetes.TLSRouteMustHaveResolvedRefsConditionsTrue(t, suite.Client, suite.TimeoutConfig, routeNN, gwNN)

			t.Run("TLS request matching exact hostnames intersection should reach backend", func(t *testing.T) {
				t.Parallel()
				tls.MakeTLSRequestAndExpectEventuallyConsistentResponse(t, suite.RoundTripper, suite.TimeoutConfig, gwAddr, serverCertPem, nil, nil, "abc.example.com",
					http.ExpectedResponse{
						Request:   http.Request{Host: "abc.example.com", Path: "/"},
						Backend:   "tls-backend",
						Namespace: ns,
					})
			})

			t.Run("TLS request not matching hostnames intersection should not reach backend", func(t *testing.T) {
				t.Parallel()
				tls.MakeTLSConnectionAndExpectEventuallyConnectionRejection(t, suite.TimeoutConfig, gwAddr, "non.matching.com")
			})
		})

		t.Run("TLSRoutes intersect with more specific wildcard listener hostname", func(t *testing.T) {
			routes := []types.NamespacedName{
				{Namespace: ns, Name: "tlsroute-exact-hostname-x-2"},
				{Namespace: ns, Name: "tlsroute-less-specific-wc-hostname-x-2"},
			}
			gwNN := types.NamespacedName{Name: "gw-tlsroute-more-specific-wc-hostname-x-2", Namespace: ns}
			gwAddr, _ := kubernetes.GatewayAndTLSRoutesMustBeAccepted(t, suite.Client, suite.TimeoutConfig, suite.ControllerName, kubernetes.NewGatewayRef(gwNN), routes...)

			for _, routeNN := range routes {
				kubernetes.TLSRouteMustHaveResolvedRefsConditionsTrue(t, suite.Client, suite.TimeoutConfig, routeNN, gwNN)
			}

			t.Run("TLS request matching exact hostnames intersection should reach backend", func(t *testing.T) {
				t.Parallel()
				tls.MakeTLSRequestAndExpectEventuallyConsistentResponse(t, suite.RoundTripper, suite.TimeoutConfig, gwAddr, serverCertPem, nil, nil, "abc.example.com",
					http.ExpectedResponse{
						Request:   http.Request{Host: "abc.example.com", Path: "/"},
						Backend:   "tls-backend",
						Namespace: ns,
					})
			})

			t.Run("TLS request matching wildcard hostnames intersection should reach backend 2", func(t *testing.T) {
				t.Parallel()
				tls.MakeTLSRequestAndExpectEventuallyConsistentResponse(t, suite.RoundTripper, suite.TimeoutConfig, gwAddr, serverCertPem, nil, nil, "other.example.com",
					http.ExpectedResponse{
						Request:   http.Request{Host: "other.example.com", Path: "/"},
						Backend:   "tls-backend-2",
						Namespace: ns,
					})
			})

			t.Run("TLS request not matching hostnames intersection should not reach backend", func(t *testing.T) {
				t.Parallel()
				tls.MakeTLSConnectionAndExpectEventuallyConnectionRejection(t, suite.TimeoutConfig, gwAddr, "non.matching.com")
			})
		})

		t.Run("TLSRoutes intersect with less specific wildcard listener hostname", func(t *testing.T) {
			routes := []types.NamespacedName{
				{Namespace: ns, Name: "tlsroute-exact-hostname-x-3"},
				{Namespace: ns, Name: "tlsroute-more-specific-wc-hostname-x-3"},
			}
			gwNN := types.NamespacedName{Name: "gw-tlsroute-less-specific-wc-hostname-x-3", Namespace: ns}
			gwAddr, _ := kubernetes.GatewayAndTLSRoutesMustBeAccepted(t, suite.Client, suite.TimeoutConfig, suite.ControllerName, kubernetes.NewGatewayRef(gwNN), routes...)

			for _, routeNN := range routes {
				kubernetes.TLSRouteMustHaveResolvedRefsConditionsTrue(t, suite.Client, suite.TimeoutConfig, routeNN, gwNN)
			}

			t.Run("TLS request matching exact hostnames intersection should reach backend", func(t *testing.T) {
				t.Parallel()
				tls.MakeTLSRequestAndExpectEventuallyConsistentResponse(t, suite.RoundTripper, suite.TimeoutConfig, gwAddr, serverCertPem, nil, nil, "abc.example.com",
					http.ExpectedResponse{
						Request:   http.Request{Host: "abc.example.com", Path: "/"},
						Backend:   "tls-backend",
						Namespace: ns,
					})
			})

			t.Run("TLS request matching wildcard hostnames intersection should reach backend 2", func(t *testing.T) {
				t.Parallel()
				tls.MakeTLSRequestAndExpectEventuallyConsistentResponse(t, suite.RoundTripper, suite.TimeoutConfig, gwAddr, serverCertPem, nil, nil, "other.example.com",
					http.ExpectedResponse{
						Request:   http.Request{Host: "other.example.com", Path: "/"},
						Backend:   "tls-backend-2",
						Namespace: ns,
					})
			})

			t.Run("TLS request not matching hostnames intersection should not reach backend", func(t *testing.T) {
				t.Parallel()
				tls.MakeTLSConnectionAndExpectEventuallyConnectionRejection(t, suite.TimeoutConfig, gwAddr, "non.matching.com")
			})
		})

		t.Run("TLSRoutes intersect with empty listener hostname", func(t *testing.T) {
			routes := []types.NamespacedName{
				{Namespace: ns, Name: "tlsroute-exact-hostname-x-4"},
				{Namespace: ns, Name: "tlsroute-less-specific-wc-hostname-x-4"},
			}
			gwNN := types.NamespacedName{Name: "gw-tlsroute-empty-hostname-x-4", Namespace: ns}
			gwAddr, _ := kubernetes.GatewayAndTLSRoutesMustBeAccepted(t, suite.Client, suite.TimeoutConfig, suite.ControllerName, kubernetes.NewGatewayRef(gwNN), routes...)

			for _, routeNN := range routes {
				kubernetes.TLSRouteMustHaveResolvedRefsConditionsTrue(t, suite.Client, suite.TimeoutConfig, routeNN, gwNN)
			}

			t.Run("TLS request matching exact hostnames intersection should reach backend", func(t *testing.T) {
				t.Parallel()
				tls.MakeTLSRequestAndExpectEventuallyConsistentResponse(t, suite.RoundTripper, suite.TimeoutConfig, gwAddr, serverCertPem, nil, nil, "abc.example.com",
					http.ExpectedResponse{
						Request:   http.Request{Host: "abc.example.com", Path: "/"},
						Backend:   "tls-backend",
						Namespace: ns,
					})
			})

			t.Run("TLS request matching wildcard hostnames intersection should reach backend 2", func(t *testing.T) {
				t.Parallel()
				tls.MakeTLSRequestAndExpectEventuallyConsistentResponse(t, suite.RoundTripper, suite.TimeoutConfig, gwAddr, serverCertPem, nil, nil, "other.example.com",
					http.ExpectedResponse{
						Request:   http.Request{Host: "other.example.com", Path: "/"},
						Backend:   "tls-backend-2",
						Namespace: ns,
					})
			})

			t.Run("TLS request not matching hostnames intersection should not reach backend", func(t *testing.T) {
				t.Parallel()
				tls.MakeTLSConnectionAndExpectEventuallyConnectionRejection(t, suite.TimeoutConfig, gwAddr, "non.matching.org")
			})
		})
	},
}
