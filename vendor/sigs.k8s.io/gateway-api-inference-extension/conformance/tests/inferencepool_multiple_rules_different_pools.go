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
	"testing"

	"k8s.io/apimachinery/pkg/types"
	gwhttp "sigs.k8s.io/gateway-api/conformance/utils/http"
	"sigs.k8s.io/gateway-api/conformance/utils/suite"
	gatewayfeatures "sigs.k8s.io/gateway-api/pkg/features"

	"sigs.k8s.io/gateway-api-inference-extension/conformance/resources"
	"sigs.k8s.io/gateway-api-inference-extension/conformance/utils/features"
	k8sutils "sigs.k8s.io/gateway-api-inference-extension/conformance/utils/kubernetes"
)

func init() {
	ConformanceTests = append(ConformanceTests, HTTPRouteMultipleRulesDifferentPools)
}

var HTTPRouteMultipleRulesDifferentPools = suite.ConformanceTest{
	ShortName:   "HTTPRouteMultipleRulesDifferentPools",
	Description: "An HTTPRoute with two rules routing to two different InferencePools",
	Manifests:   []string{"tests/inferencepool_multiple_rules_different_pools.yaml"},
	Features: []gatewayfeatures.FeatureName{
		gatewayfeatures.SupportGateway,
		gatewayfeatures.SupportHTTPRoute,
		features.SupportInferencePool,
	},
	Test: func(t *testing.T, s *suite.ConformanceTestSuite) {
		const (
			routeName     = "httproute-multiple-rules-different-pools"
			primaryPath   = "/primary"
			secondaryPath = "/secondary"

			primaryPodBackendPrefix   = "primary-inference-model-server"
			secondaryPodBackendPrefix = "secondary-inference-model-server"
		)

		primaryPoolNN := resources.PrimaryInferencePoolNN
		secondaryPoolNN := resources.SecondaryInferencePoolNN
		routeNN := types.NamespacedName{Name: routeName, Namespace: resources.AppBackendNamespace}
		gatewayNN := resources.PrimaryGatewayNN

		t.Run("Wait for resources to be accepted", func(t *testing.T) {
			k8sutils.HTTPRouteAndInferencePoolMustBeAcceptedAndRouteAccepted(t, s.Client, routeNN, gatewayNN, primaryPoolNN)
			k8sutils.HTTPRouteAndInferencePoolMustBeAcceptedAndRouteAccepted(t, s.Client, routeNN, gatewayNN, secondaryPoolNN)
		})

		t.Run("Traffic should be routed to the correct pool based on path", func(t *testing.T) {
			gwAddr := k8sutils.GetGatewayEndpoint(t, s.Client, s.TimeoutConfig, gatewayNN)

			t.Run("request to primary pool", func(t *testing.T) {
				gwhttp.MakeRequestAndExpectEventuallyConsistentResponse(t, s.RoundTripper,
					s.TimeoutConfig, gwAddr, gwhttp.ExpectedResponse{
						Request: gwhttp.Request{
							Path: primaryPath,
						},
						Backend:   primaryPodBackendPrefix, // Make sure the request is reaching the primary backend.
						Namespace: resources.AppBackendNamespace,
					})
			})

			t.Run("request to secondary pool", func(t *testing.T) {
				gwhttp.MakeRequestAndExpectEventuallyConsistentResponse(t, s.RoundTripper,
					s.TimeoutConfig, gwAddr, gwhttp.ExpectedResponse{
						Request: gwhttp.Request{
							Path: secondaryPath,
						},
						Backend:   secondaryPodBackendPrefix, // Make sure the request is reaching the secondary backend.
						Namespace: resources.AppBackendNamespace,
					})
			})
		})
	},
}
