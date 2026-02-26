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
	"sigs.k8s.io/gateway-api/conformance/utils/kubernetes"
	"sigs.k8s.io/gateway-api/conformance/utils/suite"
	"sigs.k8s.io/gateway-api/pkg/features"
)

func init() {
	ConformanceTests = append(ConformanceTests, GatewayInvalidTLSBackendConfiguration)
}

var GatewayInvalidTLSBackendConfiguration = suite.ConformanceTest{
	ShortName:   "GatewayInvalidTLSBackendConfiguration",
	Description: "A Gateway should have ResolvedRefs condition set false if the Gateway has an invalid backend TLS configuration",
	Features: []features.FeatureName{
		features.SupportGateway,
		features.SupportGatewayBackendClientCertificate,
		features.SupportHTTPRoute,
		features.SupportBackendTLSPolicy,
	},
	Manifests: []string{"tests/gateway-invalid-tls-backend-configuration.yaml"},
	Test: func(t *testing.T, s *suite.ConformanceTestSuite) {
		testCases := []struct {
			name                  string
			gatewayNamespacedName types.NamespacedName
			resolveRefsReason     gatewayv1.GatewayConditionReason
		}{
			{
				name:                  "Nonexistent secret referenced as ClientCertificateRef in Gateway backend TLS configuration",
				gatewayNamespacedName: types.NamespacedName{Name: "gateway-client-certificate-nonexistent-secret", Namespace: "gateway-conformance-infra"},
				resolveRefsReason:     gatewayv1.GatewayReasonInvalidClientCertificateRef,
			},
			{
				name:                  "Unsupported group resource referenced as ClientCertificateRef in Gateway backend TLS configuration",
				gatewayNamespacedName: types.NamespacedName{Name: "gateway-client-certificate-unsupported-group", Namespace: "gateway-conformance-infra"},
				resolveRefsReason:     gatewayv1.GatewayReasonInvalidClientCertificateRef,
			},
			{
				name:                  "Unsupported kind resource referenced as ClientCertificateRef inGateway backend TLS configuration",
				gatewayNamespacedName: types.NamespacedName{Name: "gateway-client-certificate-unsupported-kind", Namespace: "gateway-conformance-infra"},
				resolveRefsReason:     gatewayv1.GatewayReasonInvalidClientCertificateRef,
			},
			{
				name:                  "Malformed secret referenced as ClientCertificateRef in Gateway backend TLS configuration",
				gatewayNamespacedName: types.NamespacedName{Name: "gateway-client-certificate-malformed-secret", Namespace: "gateway-conformance-infra"},
				resolveRefsReason:     gatewayv1.GatewayReasonInvalidClientCertificateRef,
			},
			{
				name:                  "Secret referenced from another namespace without any ReferenceGrant as ClientCertificateRef in Gateway backend TLS configuration",
				gatewayNamespacedName: types.NamespacedName{Name: "gateway-client-certificate-missing-reference-grant", Namespace: "gateway-conformance-infra"},
				resolveRefsReason:     gatewayv1.GatewayReasonRefNotPermitted,
			},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				t.Parallel()
				kubernetes.GatewayMustHaveLatestConditions(t, s.Client, s.TimeoutConfig, tc.gatewayNamespacedName)

				kubernetes.GatewayMustHaveCondition(t, s.Client, s.TimeoutConfig, tc.gatewayNamespacedName, metav1.Condition{
					Type:   string(gatewayv1.GatewayConditionResolvedRefs),
					Status: metav1.ConditionFalse,
					Reason: string(tc.resolveRefsReason),
				})

				kubernetes.GatewayMustHaveCondition(t, s.Client, s.TimeoutConfig, tc.gatewayNamespacedName, metav1.Condition{
					Type:   string(gatewayv1.GatewayConditionAccepted),
					Status: metav1.ConditionTrue,
					Reason: string(gatewayv1.GatewayReasonAccepted),
				})
			})
		}
	},
}
