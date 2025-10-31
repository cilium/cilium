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
	ConformanceTests = append(ConformanceTests, BackendTLSPolicyConflictResolution)
}

var BackendTLSPolicyConflictResolution = suite.ConformanceTest{
	ShortName:   "BackendTLSPolicyConflictResolution",
	Description: "Verifies that when multiple BackendTLSPolicies target the same Service, only one policy is accepted while conflicting policies are rejected, and traffic continues to route successfully.",
	Features: []features.FeatureName{
		features.SupportGateway,
		features.SupportHTTPRoute,
		features.SupportBackendTLSPolicy,
	},
	Manifests: []string{"tests/backendtlspolicy-conflict-resolution.yaml"},
	Test: func(t *testing.T, suite *suite.ConformanceTestSuite) {
		ns := "gateway-conformance-infra"
		routeNN := types.NamespacedName{Name: "backendtlspolicy-conflict-resolution", Namespace: ns}
		gwNN := types.NamespacedName{Name: "same-namespace", Namespace: ns}

		kubernetes.NamespacesMustBeReady(t, suite.Client, suite.TimeoutConfig, []string{ns})
		gwAddr := kubernetes.GatewayAndRoutesMustBeAccepted(t, suite.Client, suite.TimeoutConfig, suite.ControllerName, kubernetes.NewGatewayRef(gwNN), &gatewayv1.HTTPRoute{}, false, routeNN)
		kubernetes.HTTPRouteMustHaveResolvedRefsConditionsTrue(t, suite.Client, suite.TimeoutConfig, routeNN, gwNN)

		acceptedCond := metav1.Condition{
			Type:   string(gatewayv1.PolicyConditionAccepted),
			Status: metav1.ConditionTrue,
			Reason: string(gatewayv1.PolicyReasonAccepted),
		}
		conflictedCond := metav1.Condition{
			Type:   string(gatewayv1.PolicyConditionAccepted),
			Status: metav1.ConditionFalse,
			Reason: string(gatewayv1.PolicyReasonConflicted),
		}

		t.Run("Conflicting BackendTLSPolicies targeting the same Service without a section name", func(t *testing.T) {
			t.Run("First BackendTLSPolicy should be accepted", func(t *testing.T) {
				policyNN := types.NamespacedName{Name: "conflicted-without-section-name-1", Namespace: ns}
				kubernetes.BackendTLSPolicyMustHaveCondition(t, suite.Client, suite.TimeoutConfig, policyNN, gwNN, acceptedCond)
			})

			t.Run("Second BackendTLSPolicy should have a false Accepted condition with reason Conflicted ", func(t *testing.T) {
				// This is not specific to BackendTLSPolicy, it follows the conflict-resolution rules, as defined in GEP-713.
				conflictedPolicyNN := types.NamespacedName{Name: "conflicted-without-section-name-2", Namespace: ns}
				kubernetes.BackendTLSPolicyMustHaveCondition(t, suite.Client, suite.TimeoutConfig, conflictedPolicyNN, gwNN, conflictedCond)
			})

			t.Run("HTTP request sent to Service using the accepted BackendTLSPolicy should succeed", func(t *testing.T) {
				h.MakeRequestAndExpectEventuallyConsistentResponse(t, suite.RoundTripper, suite.TimeoutConfig, gwAddr,
					h.ExpectedResponse{
						Namespace: ns,
						Request: h.Request{
							Host: "abc.example.com",
							Path: "/backendtlspolicy-conflicted-without-section-name",
							SNI:  "other.example.com",
						},
						Response: h.Response{StatusCode: 200},
					})
			})
		})

		t.Run("Conflicting BackendTLSPolicies targeting the same Service with the same section name", func(t *testing.T) {
			t.Run("First BackendTLSPolicy should be accepted", func(t *testing.T) {
				policyNN := types.NamespacedName{Name: "conflicted-with-section-name-1", Namespace: ns}
				kubernetes.BackendTLSPolicyMustHaveCondition(t, suite.Client, suite.TimeoutConfig, policyNN, gwNN, acceptedCond)
			})

			t.Run("Second BackendTLSPolicy should have a false Accepted condition with reason Conflicted ", func(t *testing.T) {
				// This is not specific to BackendTLSPolicy, it follows the conflict-resolution rules, as defined in GEP-713.
				conflictedPolicyNN := types.NamespacedName{Name: "conflicted-with-section-name-2", Namespace: ns}
				kubernetes.BackendTLSPolicyMustHaveCondition(t, suite.Client, suite.TimeoutConfig, conflictedPolicyNN, gwNN, conflictedCond)
			})

			t.Run("HTTP request sent to Service using the accepted BackendTLSPolicy should succeed", func(t *testing.T) {
				h.MakeRequestAndExpectEventuallyConsistentResponse(t, suite.RoundTripper, suite.TimeoutConfig, gwAddr,
					h.ExpectedResponse{
						Namespace: ns,
						Request: h.Request{
							Host: "abc.example.com",
							Path: "/backendtlspolicy-conflicted-with-section-name",
							SNI:  "other.example.com",
						},
						Response: h.Response{StatusCode: 200},
					})
			})
		})

		t.Run("BackendTLSPolicies targeting the same Service with and without a section name", func(t *testing.T) {
			t.Run("BackendTLSPolicy with section name should be accepted", func(t *testing.T) {
				policyNN := types.NamespacedName{Name: "not-conflicted-with-section-name", Namespace: ns}
				kubernetes.BackendTLSPolicyMustHaveCondition(t, suite.Client, suite.TimeoutConfig, policyNN, gwNN, acceptedCond)
			})

			t.Run("BackendTLSPolicy without section name should be accepted", func(t *testing.T) {
				policyNN := types.NamespacedName{Name: "not-conflicted-without-section-name", Namespace: ns}
				kubernetes.BackendTLSPolicyMustHaveCondition(t, suite.Client, suite.TimeoutConfig, policyNN, gwNN, acceptedCond)
			})

			t.Run("HTTP request sent to Service using the BackendTLSPolicy with section name should succeed", func(t *testing.T) {
				h.MakeRequestAndExpectEventuallyConsistentResponse(t, suite.RoundTripper, suite.TimeoutConfig, gwAddr,
					h.ExpectedResponse{
						Namespace: ns,
						Request: h.Request{
							Host: "abc.example.com",
							Path: "/backendtlspolicy-not-conflicted-with-section-name",
							SNI:  "other.example.com",
						},
						Response: h.Response{StatusCode: 200},
					})
			})
			t.Run("HTTP request sent to Service using the BackendTLSPolicy without section name should succeed", func(t *testing.T) {
				h.MakeRequestAndExpectEventuallyConsistentResponse(t, suite.RoundTripper, suite.TimeoutConfig, gwAddr,
					h.ExpectedResponse{
						Namespace: ns,
						Request: h.Request{
							Host: "abc.example.com",
							Path: "/backendtlspolicy-not-conflicted-without-section-name",
							SNI:  "abc.example.com",
						},
						Response: h.Response{StatusCode: 200},
					})
			})
		})
	},
}
