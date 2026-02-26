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
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
	"sigs.k8s.io/gateway-api/conformance/utils/kubernetes"
	"sigs.k8s.io/gateway-api/conformance/utils/suite"
	"sigs.k8s.io/gateway-api/pkg/features"
)

func init() {
	ConformanceTests = append(ConformanceTests, GatewayInvalidFrontendClientCertificateValidation)
}

var GatewayInvalidFrontendClientCertificateValidation = suite.ConformanceTest{
	ShortName:   "GatewayInvalidFrontendClientCertificateValidation",
	Description: "Gateway's should reject invalid Client Certificate Validation Config",
	Features: []features.FeatureName{
		features.SupportGateway,
		features.SupportHTTPRoute,
		features.SupportReferenceGrant,
		features.SupportGatewayFrontendClientCertificateValidation,
	},
	Manifests: []string{"tests/gateway-with-invalid-clientcertificate-validation.yaml"},
	Test: func(t *testing.T, suite *suite.ConformanceTestSuite) {
		// Validate that invalid configuration for Default and PerPort client certificate validation
		// impacts only status of affected Listener.
		t.Run("Validate status for invalid client certificate configuration", func(t *testing.T) {
			gwNN := types.NamespacedName{Name: "gateway-with-invalid-client-cert-validation", Namespace: "gateway-conformance-infra"}
			cases := []struct {
				name               string
				lName              string
				expectedConditions []metav1.Condition
			}{
				{
					name:  "default valid configuration",
					lName: "https",
					expectedConditions: []metav1.Condition{
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
					},
				},
				{
					name:  "unresolved reference",
					lName: "https-unresolved",
					expectedConditions: []metav1.Condition{
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
					},
				},
				{
					name:  "invalid kind",
					lName: "https-invalid-kind",
					expectedConditions: []metav1.Condition{
						{
							Type:   string(gatewayv1.ListenerConditionResolvedRefs),
							Status: metav1.ConditionFalse,
							Reason: string(gatewayv1.ListenerReasonInvalidCACertificateKind),
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
					},
				},
				{
					name:  "reference grant missing",
					lName: "https-grant-missing",
					expectedConditions: []metav1.Condition{
						{
							Type:   string(gatewayv1.ListenerConditionResolvedRefs),
							Status: metav1.ConditionFalse,
							Reason: string(gatewayv1.ListenerReasonRefNotPermitted),
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
					},
				},
			}
			for _, tc := range cases {
				t.Run(tc.name, func(t *testing.T) {
					kubernetes.GatewayListenerMustHaveConditions(t, suite.Client, suite.TimeoutConfig, gwNN, tc.lName, tc.expectedConditions)
				})
			}
		})
	},
}
