/*
Copyright 2025 The Kubernetes Authors.

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
	"net/http"
	"testing"

	"k8s.io/apimachinery/pkg/types"
	gwhttp "sigs.k8s.io/gateway-api/conformance/utils/http"
	"sigs.k8s.io/gateway-api/conformance/utils/suite"

	"sigs.k8s.io/gateway-api-inference-extension/conformance/resources"
	k8sutils "sigs.k8s.io/gateway-api-inference-extension/conformance/utils/kubernetes"
)

func init() {
	ConformanceTests = append(ConformanceTests, HTTPRouteMultipleGatewaysDifferentPools)
}

var HTTPRouteMultipleGatewaysDifferentPools = suite.ConformanceTest{
	ShortName:   "HTTPRouteMultipleGatewaysDifferentPools",
	Description: "Validates two HTTPRoutes on different Gateways successfully referencing different InferencePools and routes traffic accordingly.",
	Manifests:   []string{"tests/httproute_multiple_gateways_different_pools.yaml"},
	Test: func(t *testing.T, s *suite.ConformanceTestSuite) {
		const (
			primaryBackendPodName = "primary-inference-model-server"
			primaryRoutePath      = "/test-primary-gateway"
			primaryRouteHostname  = "primary.example.com"

			secondaryBackendPodName = "secondary-inference-model-server"
			secondaryRoutePath      = "/test-secondary-gateway"
			secondaryRouteHostname  = "secondary.example.com"
		)

		routeForPrimaryGWNN := types.NamespacedName{Name: "route-for-primary-gateway", Namespace: resources.AppBackendNamespace}
		routeForSecondaryGWNN := types.NamespacedName{Name: "route-for-secondary-gateway", Namespace: resources.AppBackendNamespace}
		primaryPoolNN := resources.PrimaryInferencePoolNN
		secondaryPoolNN := resources.SecondaryInferencePoolNN
		primaryGatewayNN := resources.PrimaryGatewayNN
		secondaryGatewayNN := resources.SecondaryGatewayNN

		t.Run("Primary HTTPRoute, InferencePool, and Gateway path: verify status and traffic", func(t *testing.T) {
			k8sutils.HTTPRouteAndInferencePoolMustBeAcceptedAndRouteAccepted(
				t,
				s.Client,
				routeForPrimaryGWNN,
				primaryGatewayNN,
				primaryPoolNN,
			)

			primaryGwAddr := k8sutils.GetGatewayEndpoint(t, s.Client, s.TimeoutConfig, primaryGatewayNN)

			gwhttp.MakeRequestAndExpectEventuallyConsistentResponse(
				t,
				s.RoundTripper,
				s.TimeoutConfig,
				primaryGwAddr,
				gwhttp.ExpectedResponse{
					Request: gwhttp.Request{
						Host: primaryRouteHostname,
						Path: primaryRoutePath,
					},
					Response: gwhttp.Response{
						StatusCodes: []int{http.StatusOK},
					},
					Backend:   primaryBackendPodName,
					Namespace: resources.AppBackendNamespace,
				},
			)
		})

		t.Run("Secondary HTTPRoute, InferencePool, and Gateway path: verify status and traffic", func(t *testing.T) {
			k8sutils.HTTPRouteAndInferencePoolMustBeAcceptedAndRouteAccepted(
				t,
				s.Client,
				routeForSecondaryGWNN,
				secondaryGatewayNN,
				secondaryPoolNN,
			)

			secondaryGwAddr := k8sutils.GetGatewayEndpoint(t, s.Client, s.TimeoutConfig, secondaryGatewayNN)

			gwhttp.MakeRequestAndExpectEventuallyConsistentResponse(
				t,
				s.RoundTripper,
				s.TimeoutConfig,
				secondaryGwAddr,
				gwhttp.ExpectedResponse{
					Request: gwhttp.Request{
						Host: secondaryRouteHostname,
						Path: secondaryRoutePath,
					},
					Response: gwhttp.Response{
						StatusCodes: []int{http.StatusOK},
					},
					Backend:   secondaryBackendPodName,
					Namespace: resources.AppBackendNamespace,
				},
			)
		})
	},
}
