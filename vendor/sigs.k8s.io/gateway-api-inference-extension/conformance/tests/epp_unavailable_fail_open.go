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

	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/types"
	gwhttp "sigs.k8s.io/gateway-api/conformance/utils/http"
	"sigs.k8s.io/gateway-api/conformance/utils/suite"
	gatewayfeatures "sigs.k8s.io/gateway-api/pkg/features"

	"sigs.k8s.io/gateway-api-inference-extension/conformance/resources"
	"sigs.k8s.io/gateway-api-inference-extension/conformance/utils/config"
	"sigs.k8s.io/gateway-api-inference-extension/conformance/utils/features"
	"sigs.k8s.io/gateway-api-inference-extension/conformance/utils/headers"
	k8sutils "sigs.k8s.io/gateway-api-inference-extension/conformance/utils/kubernetes"
)

func init() {
	ConformanceTests = append(ConformanceTests, EppUnAvailableFailOpen)
}

var EppUnAvailableFailOpen = suite.ConformanceTest{
	ShortName:   "EppUnAvailableFailOpen",
	Description: "Inference gateway should send traffic to backends even when the EPP is unavailable (fail-open)",
	Manifests:   []string{"tests/epp_unavailable_fail_open.yaml"},
	Features: []gatewayfeatures.FeatureName{
		features.SupportInferencePool,
		gatewayfeatures.SupportGateway,
	},
	Test: func(t *testing.T, s *suite.ConformanceTestSuite) {
		const (
			hostname            = "secondary.example.com"
			path                = "/failopen-pool-test"
			appPodBackendPrefix = "secondary-inference-model-server"
			requestBody         = `{
                "model": "conformance-fake-model",
                "prompt": "Write as if you were a critic: San Francisco"
            }`
		)

		httpRouteNN := types.NamespacedName{Name: "httproute-for-failopen-pool-gw", Namespace: resources.AppBackendNamespace}
		gatewayNN := resources.SecondaryGatewayNN
		k8sutils.HTTPRouteMustBeAcceptedAndResolved(t, s.Client, s.TimeoutConfig, httpRouteNN, gatewayNN)
		k8sutils.InferencePoolMustBeAcceptedByParent(t, s.Client, resources.SecondaryInferencePoolNN, gatewayNN)
		gwAddr := k8sutils.GetGatewayEndpoint(t, s.Client, s.TimeoutConfig, gatewayNN)

		pods, err := k8sutils.GetPodsWithLabel(t, s.Client, resources.AppBackendNamespace,
			map[string]string{"app": resources.SecondaryModelServerAppLabel}, s.TimeoutConfig)
		require.NoError(t, err, "Failed to get backend pods")
		require.Len(t, pods, resources.ModelServerPodReplicas, "Expected to find %d backend pod, but found %d.", resources.ModelServerPodReplicas, len(pods))

		targetPodIP := pods[0].Status.PodIP
		t.Run("Phase 1: Verify baseline connectivity with EPP available", func(t *testing.T) {
			t.Log("Sending request to ensure the Gateway and EPP are working correctly...")
			gwhttp.MakeRequestAndExpectEventuallyConsistentResponse(
				t,
				s.RoundTripper,
				s.TimeoutConfig,
				gwAddr,
				gwhttp.ExpectedResponse{
					Request: gwhttp.Request{
						Host: hostname,
						Path: path,
						Headers: map[string]string{
							headers.HeaderTestEppEndPointSelectionKey: targetPodIP,
						},
						Method: http.MethodPost,
						Body:   requestBody,
					},
					Response: gwhttp.Response{
						StatusCodes: []int{http.StatusOK},
					},
					Backend:   pods[0].Name, // Make sure the request is from the targetPod when the EPP is alive.
					Namespace: resources.AppBackendNamespace,
				},
			)
		})

		t.Run("Phase 2: Verify fail-open behavior after EPP becomes unavailable", func(t *testing.T) {
			t.Logf("Making EPP service %v unavailable...", resources.PrimaryEppServiceNN)
			timeconfig := config.DefaultInferenceExtensionTimeoutConfig()
			restore, err := k8sutils.MakeServiceUnavailable(t, s.Client, resources.PrimaryEppServiceNN, timeconfig.ServiceUpdateTimeout)
			t.Cleanup(restore)
			require.NoError(t, err, "Failed to make the EPP service %v unavailable", resources.PrimaryEppServiceNN)

			t.Log("Sending request again, expecting success to verify fail-open...")
			gwhttp.MakeRequestAndExpectEventuallyConsistentResponse(
				t,
				s.RoundTripper,
				s.TimeoutConfig,
				gwAddr,
				gwhttp.ExpectedResponse{
					Request: gwhttp.Request{
						Host: hostname,
						Path: path,
						Headers: map[string]string{
							headers.HeaderTestEppEndPointSelectionKey: targetPodIP,
						},
						Method: http.MethodPost,
						Body:   requestBody,
					},
					Response: gwhttp.Response{
						StatusCodes: []int{http.StatusOK},
					},
					Backend:   appPodBackendPrefix, // Only checks the prefix since the EPP is not alive and the response can return from any Pod.
					Namespace: resources.AppBackendNamespace,
				},
			)
		})
	},
}
