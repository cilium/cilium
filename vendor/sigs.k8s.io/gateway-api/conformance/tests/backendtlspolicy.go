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
	"sigs.k8s.io/gateway-api/apis/v1alpha2"
	h "sigs.k8s.io/gateway-api/conformance/utils/http"
	"sigs.k8s.io/gateway-api/conformance/utils/kubernetes"
	"sigs.k8s.io/gateway-api/conformance/utils/suite"
	"sigs.k8s.io/gateway-api/conformance/utils/tls"
	"sigs.k8s.io/gateway-api/pkg/features"
)

func init() {
	ConformanceTests = append(ConformanceTests, BackendTLSPolicy)
}

var BackendTLSPolicy = suite.ConformanceTest{
	ShortName:   "BackendTLSPolicy",
	Description: "BackendTLSPolicy must be used to configure TLS connection between gateway and backend",
	Features: []features.FeatureName{
		features.SupportGateway,
		features.SupportHTTPRoute,
		features.SupportBackendTLSPolicy,
	},
	Manifests: []string{"tests/backendtlspolicy.yaml"},
	Test: func(t *testing.T, suite *suite.ConformanceTestSuite) {
		ns := "gateway-conformance-infra"
		routeNN := types.NamespacedName{Name: "gateway-conformance-infra-test", Namespace: ns}
		gwNN := types.NamespacedName{Name: "gateway-backendtlspolicy", Namespace: ns}

		kubernetes.NamespacesMustBeReady(t, suite.Client, suite.TimeoutConfig, []string{ns})
		gwAddr := kubernetes.GatewayAndRoutesMustBeAccepted(t, suite.Client, suite.TimeoutConfig, suite.ControllerName, kubernetes.NewGatewayRef(gwNN), &gatewayv1.HTTPRoute{}, false, routeNN)
		kubernetes.HTTPRouteMustHaveResolvedRefsConditionsTrue(t, suite.Client, suite.TimeoutConfig, routeNN, gwNN)

		policyCond := metav1.Condition{
			Type:   string(v1alpha2.PolicyConditionAccepted),
			Status: metav1.ConditionTrue,
			Reason: string(v1alpha2.PolicyReasonAccepted),
		}

		validPolicyNN := types.NamespacedName{Name: "normative-test-backendtlspolicy", Namespace: ns}
		kubernetes.BackendTLSPolicyMustHaveCondition(t, suite.Client, suite.TimeoutConfig, validPolicyNN, gwNN, policyCond)

		invalidPolicyNN := types.NamespacedName{Name: "backendtlspolicy-host-mismatch", Namespace: ns}
		kubernetes.BackendTLSPolicyMustHaveCondition(t, suite.Client, suite.TimeoutConfig, invalidPolicyNN, gwNN, policyCond)

		invalidCertPolicyNN := types.NamespacedName{Name: "backendtlspolicy-cert-mismatch", Namespace: ns}
		kubernetes.BackendTLSPolicyMustHaveCondition(t, suite.Client, suite.TimeoutConfig, invalidCertPolicyNN, gwNN, policyCond)

		serverStr := "abc.example.com"

		// Verify that the request sent to Service with valid BackendTLSPolicy should succeed.
		t.Run("HTTP request sent to Service with valid BackendTLSPolicy should succeed", func(t *testing.T) {
			h.MakeRequestAndExpectEventuallyConsistentResponse(t, suite.RoundTripper, suite.TimeoutConfig, gwAddr,
				h.ExpectedResponse{
					Namespace: ns,
					Request: h.Request{
						Host: serverStr,
						Path: "/backendTLS",
						SNI:  serverStr,
					},
					Response: h.Response{StatusCode: 200},
				})
		})

		// For the re-encrypt case, we need to use the cert for the frontend tls listener.
		certNN := types.NamespacedName{Name: "tls-checks-certificate", Namespace: ns}
		cPem, keyPem, err := GetTLSSecret(suite.Client, certNN)
		if err != nil {
			t.Fatalf("unexpected error finding TLS secret: %v", err)
		}
		// Verify that the request to a re-encrypted call to /backendTLS should succeed.
		t.Run("Re-encrypt HTTPS request sent to Service with valid BackendTLSPolicy should succeed", func(t *testing.T) {
			tls.MakeTLSRequestAndExpectEventuallyConsistentResponse(t, suite.RoundTripper, suite.TimeoutConfig, gwAddr, cPem, keyPem, serverStr,
				h.ExpectedResponse{
					Namespace: ns,
					Request: h.Request{
						Host: serverStr,
						Path: "/backendTLS",
						SNI:  serverStr,
					},
					Response: h.Response{StatusCode: 200},
				})
		})

		// Verify that the request sent to a Service targeted by a BackendTLSPolicy with mismatched host will fail.
		t.Run("HTTP request sent to Service targeted by BackendTLSPolicy with mismatched hostname should return an HTTP error", func(t *testing.T) {
			h.MakeRequestAndExpectFailure(t, suite.RoundTripper, suite.TimeoutConfig, gwAddr,
				h.ExpectedResponse{
					Namespace: ns,
					Request: h.Request{
						Host: serverStr,
						Path: "/backendTLSHostMismatch",
						SNI:  serverStr,
					},
				})
		})

		// Verify that request sent to Service targeted by BackendTLSPolicy with mismatched cert should failed.
		t.Run("HTTP request send to Service targeted by BackendTLSPolicy with mismatched cert should return HTTP error", func(t *testing.T) {
			h.MakeRequestAndExpectFailure(t, suite.RoundTripper, suite.TimeoutConfig, gwAddr,
				h.ExpectedResponse{
					Namespace: ns,
					Request: h.Request{
						Host: serverStr,
						Path: "/backendTLSCertMismatch",
						SNI:  serverStr,
					},
				})
		})
	},
}
