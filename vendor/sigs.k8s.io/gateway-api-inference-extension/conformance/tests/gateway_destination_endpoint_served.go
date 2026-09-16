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
	"sigs.k8s.io/gateway-api-inference-extension/conformance/utils/features"
	"sigs.k8s.io/gateway-api-inference-extension/conformance/utils/headers"
	k8sutils "sigs.k8s.io/gateway-api-inference-extension/conformance/utils/kubernetes"
)

func init() {
	ConformanceTests = append(ConformanceTests, GatewayDestinationEndpointServed)
}

var GatewayDestinationEndpointServed = suite.ConformanceTest{
	ShortName:   "GatewayDestinationEndpointServed",
	Description: "A conformance test to verify that the gateway correctly reports the endpoint that served the request.",
	Manifests:   []string{"tests/gateway_destination_endpoint_served.yaml"},
	Features: []gatewayfeatures.FeatureName{
		features.SupportInferencePool,
		gatewayfeatures.SupportGateway,
	},
	Test: func(t *testing.T, s *suite.ConformanceTestSuite) {
		const (
			hostname = "primary.example.com"
			path     = "/destination-endpoint-served-test"
		)

		httpRouteNN := types.NamespacedName{Name: "httproute-for-destination-endpoint-served", Namespace: resources.AppBackendNamespace}
		gatewayNN := resources.PrimaryGatewayNN
		poolNN := resources.PrimaryInferencePoolNN
		backendPodLabels := map[string]string{"app": resources.PrimaryModelServerAppLabel}

		t.Log("Verifying HTTPRoute and InferencePool are accepted and the Gateway has an address.")
		k8sutils.HTTPRouteMustBeAcceptedAndResolved(t, s.Client, s.TimeoutConfig, httpRouteNN, gatewayNN)
		k8sutils.InferencePoolMustBeAcceptedByParent(t, s.Client, poolNN, gatewayNN)
		gwAddr := k8sutils.GetGatewayEndpoint(t, s.Client, s.TimeoutConfig, gatewayNN)

		t.Logf("Fetching backend pods with labels: %v", backendPodLabels)
		pods, err := k8sutils.GetPodsWithLabel(t, s.Client, resources.AppBackendNamespace, backendPodLabels, s.TimeoutConfig)
		require.NoError(t, err, "Failed to get backend pods")
		require.Len(t, pods, resources.ModelServerPodReplicas, "Expected to find %d backend pods, but found %d.", resources.ModelServerPodReplicas, len(pods))

		podIPs := make([]string, len(pods))
		podNames := make([]string, len(pods))
		for i, pod := range pods {
			podIPs[i] = pod.Status.PodIP
			podNames[i] = pod.Name
		}

		requestBody := `{
            "model": "conformance-fake-model",
            "prompt": "Write as if you were a critic: San Francisco"
        }`
		t.Run("Request is served by the selected backend pod", func(t *testing.T) {
			for i := 0; i < len(pods); i++ {
				gwhttp.MakeRequestAndExpectEventuallyConsistentResponse(
					t,
					s.RoundTripper,
					s.TimeoutConfig,
					gwAddr,
					gwhttp.ExpectedResponse{
						Request: gwhttp.Request{
							Host:   hostname,
							Path:   path,
							Method: http.MethodPost,
							Body:   requestBody,
							Headers: map[string]string{
								headers.HeaderTestEppEndPointSelectionKey: podIPs[i],
							},
						},
						Response: gwhttp.Response{
							StatusCodes: []int{http.StatusOK},
							Headers: map[string]string{
								headers.ConformanceTestResultHeader: podIPs[i] + ":3000", // The echo server's port is 3000.
							},
						},
						Backend:   podNames[i],
						Namespace: resources.AppBackendNamespace,
					},
				)
			}
		})
	},
}
