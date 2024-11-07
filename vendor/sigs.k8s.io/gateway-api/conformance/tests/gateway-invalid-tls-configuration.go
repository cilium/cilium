/*
Copyright 2022 The Kubernetes Authors.

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

	v1 "sigs.k8s.io/gateway-api/apis/v1"
	"sigs.k8s.io/gateway-api/conformance/utils/kubernetes"
	"sigs.k8s.io/gateway-api/conformance/utils/suite"
	"sigs.k8s.io/gateway-api/pkg/features"
)

func init() {
	ConformanceTests = append(ConformanceTests, GatewayInvalidTLSConfiguration)
}

var GatewayInvalidTLSConfiguration = suite.ConformanceTest{
	ShortName:   "GatewayInvalidTLSConfiguration",
	Description: "A Gateway should fail to become ready if the Gateway has an invalid TLS configuration",
	Features: []features.FeatureName{
		features.SupportGateway,
	},
	Manifests: []string{"tests/gateway-invalid-tls-configuration.yaml"},
	Test: func(t *testing.T, s *suite.ConformanceTestSuite) {
		listeners := []v1.ListenerStatus{{
			Name: v1.SectionName("https"),
			SupportedKinds: []v1.RouteGroupKind{{
				Group: (*v1.Group)(&v1.GroupVersion.Group),
				Kind:  v1.Kind("HTTPRoute"),
			}},
			Conditions: []metav1.Condition{{
				Type:   string(v1.ListenerConditionResolvedRefs),
				Status: metav1.ConditionFalse,
				Reason: string(v1.ListenerReasonInvalidCertificateRef),
			}},
			AttachedRoutes: 0,
		}}

		testCases := []struct {
			name                  string
			gatewayNamespacedName types.NamespacedName
		}{
			{
				name:                  "Nonexistent secret referenced as CertificateRef in a Gateway listener",
				gatewayNamespacedName: types.NamespacedName{Name: "gateway-certificate-nonexistent-secret", Namespace: "gateway-conformance-infra"},
			},
			{
				name:                  "Unsupported group resource referenced as CertificateRef in a Gateway listener",
				gatewayNamespacedName: types.NamespacedName{Name: "gateway-certificate-unsupported-group", Namespace: "gateway-conformance-infra"},
			},
			{
				name:                  "Unsupported kind resource referenced as CertificateRef in a Gateway listener",
				gatewayNamespacedName: types.NamespacedName{Name: "gateway-certificate-unsupported-kind", Namespace: "gateway-conformance-infra"},
			},
			{
				name:                  "Malformed secret referenced as CertificateRef in a Gateway listener",
				gatewayNamespacedName: types.NamespacedName{Name: "gateway-certificate-malformed-secret", Namespace: "gateway-conformance-infra"},
			},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				t.Parallel()
				kubernetes.GatewayStatusMustHaveListeners(t, s.Client, s.TimeoutConfig, tc.gatewayNamespacedName, listeners)
			})
		}
	},
}
