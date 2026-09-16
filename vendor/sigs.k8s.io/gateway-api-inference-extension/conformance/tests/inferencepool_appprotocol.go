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
	"sigs.k8s.io/gateway-api/pkg/features"

	"sigs.k8s.io/gateway-api-inference-extension/conformance/resources"
	"sigs.k8s.io/gateway-api-inference-extension/conformance/utils/headers"
	k8sutils "sigs.k8s.io/gateway-api-inference-extension/conformance/utils/kubernetes"
)

func init() {
	ConformanceTests = append(ConformanceTests, InferencePoolAppProtocol)
}

var InferencePoolAppProtocol = suite.ConformanceTest{
	ShortName:   "InferencePoolAppProtocol",
	Description: "An InferencePool should honor explicit appProtocol values and default to HTTP/1.1 when appProtocol is omitted.",
	Manifests:   []string{"tests/inferencepool_appprotocol.yaml"},
	Features: []features.FeatureName{
		features.FeatureName("SupportInferencePool"),
		features.SupportGateway,
	},
	Test: func(t *testing.T, s *suite.ConformanceTestSuite) {
		gatewayNN := resources.PrimaryGatewayNN
		gwAddr := k8sutils.GetGatewayEndpoint(t, s.Client, s.TimeoutConfig, gatewayNN)

		requestBody := `{
            "model": "conformance-fake-model",
            "prompt": "Describe San Francisco in one sentence."
        }`

		testCases := []struct {
			name       string
			hostname   string
			path       string
			targetPort string
			routeNN    types.NamespacedName
			poolNN     types.NamespacedName
			labels     map[string]string
		}{
			{
				name:       "explicit cleartext HTTP/2 appProtocol",
				hostname:   "appprotocol-h2c.example.com",
				path:       "/inferencepool-app-protocol-h2c",
				targetPort: "3001",
				routeNN:    types.NamespacedName{Name: "httproute-for-inferencepool-appprotocol-h2c", Namespace: resources.AppBackendNamespace},
				poolNN:     resources.AppProtocolH2CInferencePoolNN,
				labels:     map[string]string{"app": resources.AppProtocolModelServerAppLabel},
			},
			{
				name:       "explicit HTTP/1.1 appProtocol",
				hostname:   "appprotocol-http.example.com",
				path:       "/inferencepool-app-protocol-http",
				targetPort: "3000",
				routeNN:    types.NamespacedName{Name: "httproute-for-inferencepool-appprotocol-http", Namespace: resources.AppBackendNamespace},
				poolNN:     resources.AppProtocolHTTPInferencePoolNN,
				labels:     map[string]string{"app": resources.AppProtocolModelServerAppLabel},
			},
			{
				name:       "omitted appProtocol defaults to HTTP/1.1",
				hostname:   "appprotocol-default.example.com",
				path:       "/inferencepool-app-protocol-default",
				targetPort: "3000",
				routeNN:    types.NamespacedName{Name: "httproute-for-inferencepool-appprotocol-default", Namespace: resources.AppBackendNamespace},
				poolNN:     resources.PrimaryInferencePoolNN,
				labels:     map[string]string{"app": resources.PrimaryModelServerAppLabel},
			},
		}

		// The dedicated appProtocol backend is protocol-specific per port: it
		// serves cleartext HTTP/1.1 on 3000 and h2c on 3001. A successful request
		// to the selected pod:port therefore proves the gateway honored the pool's
		// appProtocol semantics.
		for _, tc := range testCases {
			tc := tc
			t.Run(tc.name, func(t *testing.T) {
				t.Log("Verifying HTTPRoute and InferencePool are accepted.")
				k8sutils.HTTPRouteMustBeAcceptedAndResolved(t, s.Client, s.TimeoutConfig, tc.routeNN, gatewayNN)
				k8sutils.InferencePoolMustBeAcceptedByParent(t, s.Client, tc.poolNN, gatewayNN)

				pods, err := k8sutils.GetPodsWithLabel(t, s.Client, resources.AppBackendNamespace, tc.labels, s.TimeoutConfig)
				require.NoError(t, err, "Failed to get backend pods for appProtocol test")
				require.NotEmpty(t, pods, "Expected to find at least one backend pod for appProtocol test")

				for _, pod := range pods {
					pod := pod
					selectedEndpoint := pod.Status.PodIP + ":" + tc.targetPort

					t.Run("selected pod "+pod.Name, func(t *testing.T) {
						gwhttp.MakeRequestAndExpectEventuallyConsistentResponse(
							t,
							s.RoundTripper,
							s.TimeoutConfig,
							gwAddr,
							gwhttp.ExpectedResponse{
								Request: gwhttp.Request{
									Host:   tc.hostname,
									Path:   tc.path,
									Method: http.MethodPost,
									Body:   requestBody,
									Headers: map[string]string{
										headers.HeaderTestEppEndPointSelectionKey: selectedEndpoint,
									},
								},
								Response: gwhttp.Response{
									StatusCodes: []int{http.StatusOK},
									Headers: map[string]string{
										headers.ConformanceTestResultHeader: selectedEndpoint,
									},
								},
								Backend:   pod.Name,
								Namespace: resources.AppBackendNamespace,
							},
						)
					})
				}
			})
		}
	},
}
