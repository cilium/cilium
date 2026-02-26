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

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
	h "sigs.k8s.io/gateway-api/conformance/utils/http"
	"sigs.k8s.io/gateway-api/conformance/utils/kubernetes"
	"sigs.k8s.io/gateway-api/conformance/utils/suite"
	"sigs.k8s.io/gateway-api/pkg/features"
)

func init() {
	ConformanceTests = append(ConformanceTests, GatewayTLSBackendClientCertificate)
}

var GatewayTLSBackendClientCertificate = suite.ConformanceTest{
	ShortName:   "GatewayBackendClientCertificateFeature",
	Description: "A Gateway with a client certificate configured should present the certificate when connecting to a backend using TLS.",
	Features: []features.FeatureName{
		features.SupportGateway,
		features.SupportGatewayBackendClientCertificate,
		features.SupportHTTPRoute,
		features.SupportBackendTLSPolicy,
	},
	Manifests: []string{"tests/gateway-tls-backend-client-certificate.yaml"},
	Test: func(t *testing.T, suite *suite.ConformanceTestSuite) {
		ns := "gateway-conformance-infra"

		routeNN := types.NamespacedName{Name: "gateway-tls-backend-client-certificate", Namespace: ns}
		gwNN := types.NamespacedName{Name: "gateway-tls-backend-client-certificate", Namespace: ns}
		policyNN := types.NamespacedName{Name: "gateway-tls-backend-client-certificate-test", Namespace: ns}

		kubernetes.NamespacesMustBeReady(t, suite.Client, suite.TimeoutConfig, []string{ns})
		gwAddr := kubernetes.GatewayAndRoutesMustBeAccepted(t, suite.Client, suite.TimeoutConfig, suite.ControllerName, kubernetes.NewGatewayRef(gwNN), &gatewayv1.HTTPRoute{}, false, routeNN)
		kubernetes.HTTPRouteMustHaveResolvedRefsConditionsTrue(t, suite.Client, suite.TimeoutConfig, routeNN, gwNN)
		kubernetes.BackendTLSPolicyMustHaveAcceptedConditionTrue(t, suite.Client, suite.TimeoutConfig, policyNN, gwNN)

		kubernetes.GatewayMustHaveCondition(t, suite.Client, suite.TimeoutConfig, gwNN, metav1.Condition{
			Type:   string(gatewayv1.GatewayConditionResolvedRefs),
			Status: metav1.ConditionTrue,
			Reason: string(gatewayv1.GatewayReasonResolvedRefs),
		})

		t.Run("HTTP request sent to Service using TLS should succeed and the configured client certificate should be presented.", func(t *testing.T) {
			expectedClientCert, _, err := GetTLSSecret(suite.Client, types.NamespacedName{Name: "tls-checks-client-certificate", Namespace: ns})
			if err != nil {
				t.Fatalf("unexpected error finding TLS client certifcate secret: %v", err)
			}

			h.MakeRequestAndExpectEventuallyConsistentResponse(t, suite.RoundTripper, suite.TimeoutConfig, gwAddr,
				h.ExpectedResponse{
					Namespace: ns,
					Request: h.Request{
						Path:       "/",
						Host:       "abc.example.com",
						SNI:        "abc.example.com",
						ClientCert: string(expectedClientCert),
					},
					Response: h.Response{StatusCodes: []int{200}},
				})
		})
	},
}
