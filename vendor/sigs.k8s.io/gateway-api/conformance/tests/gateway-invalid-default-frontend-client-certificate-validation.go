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
	"net"
	"testing"

	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
	"sigs.k8s.io/gateway-api/conformance/utils/http"
	"sigs.k8s.io/gateway-api/conformance/utils/kubernetes"
	"sigs.k8s.io/gateway-api/conformance/utils/suite"
	"sigs.k8s.io/gateway-api/conformance/utils/tls"
	"sigs.k8s.io/gateway-api/pkg/features"
)

func init() {
	ConformanceTests = append(ConformanceTests, GatewayFrontendInvalidDefaultClientCertificateValidation)
}

var GatewayFrontendInvalidDefaultClientCertificateValidation = suite.ConformanceTest{
	ShortName:   "GatewayFrontendInvalidDefaultClientCertificateValidation",
	Description: "Invalid Gateway's default Client Certificate Validation Config should only affect HTTPS traffic",
	Features: []features.FeatureName{
		features.SupportGateway,
		features.SupportHTTPRoute,
		features.SupportGatewayFrontendClientCertificateValidation,
	},
	Manifests: []string{"tests/gateway-invalid-default-frontend-client-certificate-validation.yaml"},
	Test: func(t *testing.T, suite *suite.ConformanceTestSuite) {
		ns := "gateway-conformance-infra"

		gwNN := types.NamespacedName{Name: "invalid-default-client-validation-config", Namespace: ns}

		// Wait for gateway address to be assigned. Do not check the Status it will be done per each Listener later.
		gwAddr, err := kubernetes.WaitForGatewayAddress(t, suite.Client, suite.TimeoutConfig, kubernetes.NewGatewayRef(gwNN))
		require.NoErrorf(t, err, "timed out waiting for Gateway address to be assigned")

		// use gateway Adddress without port because we have 2 HTTPS listeners with different port
		gwAddr, _, err = net.SplitHostPort(gwAddr)
		require.NoErrorf(t, err, "Failed to split host port from gateway VIP: %v", gwAddr)

		// Get Server certificate, this certificate is the same for both listeners
		certNN := types.NamespacedName{Name: "tls-validity-checks-certificate", Namespace: ns}
		serverCertPem, _, err := GetTLSSecret(suite.Client, certNN)
		if err != nil {
			t.Fatalf("unexpected error finding TLS secret: %v", err)
		}

		t.Run("Validate tls configuration does not impact HTTP listener", func(t *testing.T) {
			expectedConditions := []metav1.Condition{
				{
					Type:   string(gatewayv1.ListenerConditionResolvedRefs),
					Status: metav1.ConditionTrue,
					Reason: "", // any reason
				},
				{
					Type:   string(gatewayv1.ListenerConditionAccepted),
					Status: metav1.ConditionTrue,
					Reason: "", // any reason
				},
				{
					Type:   string(gatewayv1.ListenerConditionProgrammed),
					Status: metav1.ConditionTrue,
					Reason: "", // any reason
				},
			}
			kubernetes.GatewayListenerMustHaveConditions(t, suite.Client, suite.TimeoutConfig, gwNN, "http", expectedConditions)

			httpAddr := net.JoinHostPort(gwAddr, "80")
			expectedSuccess := http.ExpectedResponse{
				Request:   http.Request{Host: "example.org", Path: "/"},
				Response:  http.Response{StatusCode: 200},
				Backend:   "infra-backend-v1",
				Namespace: "gateway-conformance-infra",
			}
			// send request to the first listener and validate that it is passing
			http.MakeRequestAndExpectEventuallyConsistentResponse(t, suite.RoundTripper, suite.TimeoutConfig, httpAddr, expectedSuccess)
		})

		t.Run("Validate that invalid default configuration is impacting HTTPS listener", func(t *testing.T) {
			expectedConditions := []metav1.Condition{
				{
					Type:   string(gatewayv1.ListenerConditionResolvedRefs),
					Status: metav1.ConditionFalse,
					Reason: string(gatewayv1.ListenerReasonInvalidCACertificateRef),
				},
				{
					Type:   string(gatewayv1.ListenerConditionAccepted),
					Status: metav1.ConditionFalse,
					Reason: string(gatewayv1.ListenerReasonNoValidCACertificate),
				},
				{
					Type:   string(gatewayv1.ListenerConditionProgrammed),
					Status: metav1.ConditionFalse,
					Reason: "", // any reason
				},
			}
			kubernetes.GatewayListenerMustHaveConditions(t, suite.Client, suite.TimeoutConfig, gwNN, "https", expectedConditions)

			httpsAddr := net.JoinHostPort(gwAddr, "443")
			expectedFailure := http.ExpectedResponse{
				Request:   http.Request{Host: "example.org", Path: "/"},
				Namespace: "gateway-conformance-infra",
			}
			// send request to the second listener and validate that it is failing
			tls.MakeTLSRequestAndExpectFailureResponse(t, suite.RoundTripper, httpsAddr, serverCertPem, nil, nil, "example.org", expectedFailure)
		})
	},
}
