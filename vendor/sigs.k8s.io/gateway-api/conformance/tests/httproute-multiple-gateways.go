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
	confsuite "sigs.k8s.io/gateway-api/conformance/utils/suite"
	"sigs.k8s.io/gateway-api/pkg/features"
)

func init() {
	ConformanceTests = append(ConformanceTests, HTTPRouteMultipleGateways)
}

var HTTPRouteMultipleGateways = confsuite.ConformanceTest{
	ShortName:   "HTTPRouteMultipleGateways",
	Description: "An HTTPRoute that is attached to multiple Gateways receives traffic from each Gateway independently, and shared routes are accessible via all parent Gateways while dedicated routes are only accessible via their respective parent.",
	Features: []features.FeatureName{
		features.SupportGateway,
		features.SupportHTTPRoute,
	},
	Manifests: []string{"tests/httproute-multiple-gateways.yaml"},
	Test: func(t *testing.T, suite *confsuite.ConformanceTestSuite) {
		t.Run("Gateway same-namespace", func(t *testing.T) {
			t.Parallel()

			routeNNs := []types.NamespacedName{
				{Name: "multiple-gateways-shared-route", Namespace: confsuite.InfrastructureNamespace},
				{Name: "same-namespace-dedicated-route", Namespace: confsuite.InfrastructureNamespace},
			}
			gwNN := types.NamespacedName{Name: "same-namespace", Namespace: confsuite.InfrastructureNamespace}
			gwAddr := kubernetes.GatewayAndHTTPRoutesMustBeAccepted(t, suite.Client, suite.TimeoutConfig, suite.ControllerName, kubernetes.NewGatewayRef(gwNN), routeNNs...)

			t.Run("shared route is accessible and routed to infra-backend-v1", func(t *testing.T) {
				http.MakeRequestAndExpectEventuallyConsistentResponse(t, suite.RoundTripper, suite.TimeoutConfig, gwAddr, http.ExpectedResponse{
					Request:   http.Request{Path: "/shared"},
					Response:  http.Response{StatusCode: 200},
					Backend:   confsuite.InfraBackendServiceNameV1,
					Namespace: confsuite.InfrastructureNamespace,
				})
			})
			t.Run("dedicated route is accessible and routed to infra-backend-v2", func(t *testing.T) {
				http.MakeRequestAndExpectEventuallyConsistentResponse(t, suite.RoundTripper, suite.TimeoutConfig, gwAddr, http.ExpectedResponse{
					Request:   http.Request{Path: "/"},
					Response:  http.Response{StatusCode: 200},
					Backend:   confsuite.InfraBackendServiceNameV2,
					Namespace: confsuite.InfrastructureNamespace,
				})
			})
		})

		t.Run("Gateway all-namespaces", func(t *testing.T) {
			t.Parallel()

			routeNNs := []types.NamespacedName{
				{Name: "multiple-gateways-shared-route", Namespace: confsuite.InfrastructureNamespace},
				{Name: "all-namespaces-dedicated-route", Namespace: confsuite.InfrastructureNamespace},
			}
			gwNN := types.NamespacedName{Name: "all-namespaces", Namespace: confsuite.InfrastructureNamespace}
			gwAddr := kubernetes.GatewayAndHTTPRoutesMustBeAccepted(t, suite.Client, suite.TimeoutConfig, suite.ControllerName, kubernetes.NewGatewayRef(gwNN), routeNNs...)

			t.Run("shared route is accessible and routed to infra-backend-v1", func(t *testing.T) {
				http.MakeRequestAndExpectEventuallyConsistentResponse(t, suite.RoundTripper, suite.TimeoutConfig, gwAddr, http.ExpectedResponse{
					Request:   http.Request{Path: "/shared"},
					Response:  http.Response{StatusCode: 200},
					Backend:   confsuite.InfraBackendServiceNameV1,
					Namespace: confsuite.InfrastructureNamespace,
				})
			})
			t.Run("dedicated route is accessible and routed to infra-backend-v3", func(t *testing.T) {
				http.MakeRequestAndExpectEventuallyConsistentResponse(t, suite.RoundTripper, suite.TimeoutConfig, gwAddr, http.ExpectedResponse{
					Request:   http.Request{Path: "/"},
					Response:  http.Response{StatusCode: 200},
					Backend:   confsuite.InfraBackendServiceNameV3,
					Namespace: confsuite.InfrastructureNamespace,
				})
			})
		})
	},
}
