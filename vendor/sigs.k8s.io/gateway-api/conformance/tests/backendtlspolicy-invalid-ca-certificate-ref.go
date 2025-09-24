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
	ConformanceTests = append(ConformanceTests, BackendTLSPolicyInvalidCACertificateRef)
}

var BackendTLSPolicyInvalidCACertificateRef = suite.ConformanceTest{
	ShortName:   "BackendTLSPolicyInvalidCACertificateRef",
	Description: "A BackendTLSPolicy that specifies a single invalid CACertificateRef should have the Accepted and ResolvedRefs status condition set False with appropriate reasons, and HTTP requests to a backend targeted by this policy should fail with a 5xx response.",
	Features: []features.FeatureName{
		features.SupportGateway,
		features.SupportHTTPRoute,
		features.SupportBackendTLSPolicy,
	},
	Manifests: []string{"tests/backendtlspolicy-invalid-ca-certificate-ref.yaml"},
	Test: func(t *testing.T, suite *suite.ConformanceTestSuite) {
		ns := "gateway-conformance-infra"
		routeNN := types.NamespacedName{Name: "backendtlspolicy-invalid-ca-certificate-ref", Namespace: ns}
		gwNN := types.NamespacedName{Name: "same-namespace", Namespace: ns}

		serverStr := "abc.example.com"

		kubernetes.NamespacesMustBeReady(t, suite.Client, suite.TimeoutConfig, []string{ns})
		gwAddr := kubernetes.GatewayAndRoutesMustBeAccepted(t, suite.Client, suite.TimeoutConfig, suite.ControllerName, kubernetes.NewGatewayRef(gwNN), &gatewayv1.HTTPRoute{}, false, routeNN)

		for _, policyNN := range []types.NamespacedName{
			{Name: "nonexistent-ca-certificate-ref", Namespace: ns},
			{Name: "malformed-ca-certificate-ref", Namespace: ns},
		} {
			t.Run("BackendTLSPolicy_"+policyNN.Name, func(t *testing.T) {
				t.Run("BackendTLSPolicy with a single invalid CACertificateRef has a Accepted Condition with status False and Reason NoValidCACertificate", func(t *testing.T) {
					acceptedCond := metav1.Condition{
						Type:   string(gatewayv1.PolicyConditionAccepted),
						Status: metav1.ConditionFalse,
						Reason: string(gatewayv1.BackendTLSPolicyReasonNoValidCACertificate),
					}

					kubernetes.BackendTLSPolicyMustHaveCondition(t, suite.Client, suite.TimeoutConfig, policyNN, gwNN, acceptedCond)
				})

				t.Run("BackendTLSPolicy with a single invalid CACertificateRef has a ResolvedRefs Condition with status False and Reason InvalidCACertificateRef", func(t *testing.T) {
					resolvedRefsCond := metav1.Condition{
						Type:   string(gatewayv1.BackendTLSPolicyConditionResolvedRefs),
						Status: metav1.ConditionFalse,
						Reason: string(gatewayv1.BackendTLSPolicyReasonInvalidCACertificateRef),
					}

					kubernetes.BackendTLSPolicyMustHaveCondition(t, suite.Client, suite.TimeoutConfig, policyNN, gwNN, resolvedRefsCond)
				})

				t.Run("HTTP Request to backend targeted by an invalid BackendTLSPolicy receive a 5xx", func(t *testing.T) {
					h.MakeRequestAndExpectEventuallyConsistentResponse(t, suite.RoundTripper, suite.TimeoutConfig, gwAddr,
						h.ExpectedResponse{
							Namespace: ns,
							Request: h.Request{
								Host: serverStr,
								Path: "/backendtlspolicy-" + policyNN.Name,
							},
							Response: h.Response{
								StatusCodes: []int{500, 502, 503},
							},
						})
				})
			})
		}
	},
}
