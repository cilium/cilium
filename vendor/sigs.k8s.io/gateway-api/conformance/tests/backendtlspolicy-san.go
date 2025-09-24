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
	ConformanceTests = append(ConformanceTests, BackendTLSPolicySANValidation)
}

var BackendTLSPolicySANValidation = suite.ConformanceTest{
	ShortName:   "BackendTLSPolicySANValidation",
	Description: "BackendTLSPolicySANValidation extend BackendTLSPolicy with SubjectAltNames validation",
	Features: []features.FeatureName{
		features.SupportGateway,
		features.SupportHTTPRoute,
		features.SupportBackendTLSPolicy,
		features.SupportBackendTLSPolicySANValidation,
	},
	Manifests: []string{"tests/backendtlspolicy-san.yaml"},
	Test: func(t *testing.T, suite *suite.ConformanceTestSuite) {
		ns := "gateway-conformance-infra"
		routeNN := types.NamespacedName{Name: "backendtlspolicy-san-test", Namespace: ns}
		gwNN := types.NamespacedName{Name: "same-namespace", Namespace: ns}

		kubernetes.NamespacesMustBeReady(t, suite.Client, suite.TimeoutConfig, []string{ns})
		gwAddr := kubernetes.GatewayAndRoutesMustBeAccepted(t, suite.Client, suite.TimeoutConfig, suite.ControllerName, kubernetes.NewGatewayRef(gwNN), &gatewayv1.HTTPRoute{}, false, routeNN)
		kubernetes.HTTPRouteMustHaveResolvedRefsConditionsTrue(t, suite.Client, suite.TimeoutConfig, routeNN, gwNN)

		policyCond := metav1.Condition{
			Type:   string(gatewayv1.PolicyConditionAccepted),
			Status: metav1.ConditionTrue,
			Reason: string(gatewayv1.PolicyReasonAccepted),
		}

		serverStr := "abc.example.com"

		// Verify that the request sent to Service with valid BackendTLSPolicy containing dns SAN should succeed.
		t.Run("HTTP request sent to Service with valid BackendTLSPolicy containing dns SAN should succeed", func(t *testing.T) {
			policyNN := types.NamespacedName{Name: "san-dns", Namespace: ns}
			kubernetes.BackendTLSPolicyMustHaveCondition(t, suite.Client, suite.TimeoutConfig, policyNN, gwNN, policyCond)

			h.MakeRequestAndExpectEventuallyConsistentResponse(t, suite.RoundTripper, suite.TimeoutConfig, gwAddr,
				h.ExpectedResponse{
					Namespace: ns,
					Request: h.Request{
						Host: serverStr,
						Path: "/backendtlspolicy-san-dns",
						SNI:  serverStr,
					},
					Response: h.Response{StatusCodes: []int{200}},
				})
		})

		// Verify that the request sent to a Service targeted by a BackendTLSPolicy with mismatched dns SAN should fail.
		t.Run("HTTP request sent to Service targeted by BackendTLSPolicy with mismatched dns SAN should return an HTTP error", func(t *testing.T) {
			policyNN := types.NamespacedName{Name: "san-dns-mismatch", Namespace: ns}
			kubernetes.BackendTLSPolicyMustHaveCondition(t, suite.Client, suite.TimeoutConfig, policyNN, gwNN, policyCond)

			h.MakeRequestAndExpectFailure(t, suite.RoundTripper, suite.TimeoutConfig, gwAddr,
				h.ExpectedResponse{
					Namespace: ns,
					Request: h.Request{
						Host: serverStr,
						Path: "/backendtlspolicy-san-dns-mismatch",
						SNI:  serverStr,
					},
				})
		})

		// Verify that the request sent to Service with valid BackendTLSPolicy containing uri SAN should succeed.
		t.Run("HTTP request sent to Service with valid BackendTLSPolicy containing uri SAN should succeed", func(t *testing.T) {
			policyNN := types.NamespacedName{Name: "san-uri", Namespace: ns}
			kubernetes.BackendTLSPolicyMustHaveCondition(t, suite.Client, suite.TimeoutConfig, policyNN, gwNN, policyCond)

			h.MakeRequestAndExpectEventuallyConsistentResponse(t, suite.RoundTripper, suite.TimeoutConfig, gwAddr,
				h.ExpectedResponse{
					Namespace: ns,
					Request: h.Request{
						Host: serverStr,
						Path: "/backendtlspolicy-san-uri",
						SNI:  serverStr,
					},
					Response: h.Response{StatusCodes: []int{200}},
				})
		})

		// Verify that the request sent to a Service targeted by a BackendTLSPolicy with mismatched uri SAN should fail.
		t.Run("HTTP request sent to Service targeted by BackendTLSPolicy with mismatched uri SAN should return an HTTP error", func(t *testing.T) {
			policyNN := types.NamespacedName{Name: "san-uri-mismatch", Namespace: ns}
			kubernetes.BackendTLSPolicyMustHaveCondition(t, suite.Client, suite.TimeoutConfig, policyNN, gwNN, policyCond)

			h.MakeRequestAndExpectFailure(t, suite.RoundTripper, suite.TimeoutConfig, gwAddr,
				h.ExpectedResponse{
					Namespace: ns,
					Request: h.Request{
						Host: serverStr,
						Path: "/backendtlspolicy-san-uri-mismatch",
						SNI:  serverStr,
					},
				})
		})

		// Verify that the request sent to Service with valid BackendTLSPolicy containing multi SANs should succeed.
		t.Run("HTTP request sent to Service with valid BackendTLSPolicy containing multi SAN should succeed", func(t *testing.T) {
			policyNN := types.NamespacedName{Name: "multiple-sans", Namespace: ns}
			kubernetes.BackendTLSPolicyMustHaveCondition(t, suite.Client, suite.TimeoutConfig, policyNN, gwNN, policyCond)

			h.MakeRequestAndExpectEventuallyConsistentResponse(t, suite.RoundTripper, suite.TimeoutConfig, gwAddr,
				h.ExpectedResponse{
					Namespace: ns,
					Request: h.Request{
						Host: serverStr,
						Path: "/backendtlspolicy-multiple-sans",
						SNI:  serverStr,
					},
					Response: h.Response{StatusCodes: []int{200}},
				})
		})

		// Verify that the request sent to a Service targeted by a BackendTLSPolicy with mismatched multi SAN should fail.
		t.Run("HTTP request sent to Service targeted by BackendTLSPolicy with mismatched multi SAN should return an HTTP error", func(t *testing.T) {
			policyNN := types.NamespacedName{Name: "multiple-mismatch-sans", Namespace: ns}
			kubernetes.BackendTLSPolicyMustHaveCondition(t, suite.Client, suite.TimeoutConfig, policyNN, gwNN, policyCond)

			h.MakeRequestAndExpectFailure(t, suite.RoundTripper, suite.TimeoutConfig, gwAddr,
				h.ExpectedResponse{
					Namespace: ns,
					Request: h.Request{
						Host: serverStr,
						Path: "/backendtlspolicy-multiple-mismatch-sans",
						SNI:  serverStr,
					},
				})
		})
	},
}
