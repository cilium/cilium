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

	"sigs.k8s.io/gateway-api/apis/v1alpha2"
	"sigs.k8s.io/gateway-api/conformance/utils/kubernetes"
	"sigs.k8s.io/gateway-api/conformance/utils/suite"
)

func init() {
	ConformanceTests = append(ConformanceTests, GatewaySecretReferenceGrantAllInNamespace)
}

var GatewaySecretReferenceGrantAllInNamespace = suite.ConformanceTest{
	ShortName:   "GatewaySecretReferenceGrantAllInNamespace",
	Description: "A Gateway in the gateway-conformance-infra namespace should become ready if the Gateway has a certificateRef for a Secret in the gateway-conformance-web-backend namespace and a ReferenceGrant granting permission to all Secrets in the namespace exists",
	Features:    []suite.SupportedFeature{suite.SupportReferenceGrant},
	Manifests:   []string{"tests/gateway-secret-reference-grant-specific.yaml"},
	Test: func(t *testing.T, s *suite.ConformanceTestSuite) {
		gwNN := types.NamespacedName{Name: "gateway-secret-reference-grant", Namespace: "gateway-conformance-infra"}

		t.Run("Gateway listener should have a true ResolvedRefs condition and a true Ready condition", func(t *testing.T) {
			listeners := []v1alpha2.ListenerStatus{{
				Name: v1alpha2.SectionName("https"),
				SupportedKinds: []v1alpha2.RouteGroupKind{{
					Group: (*v1alpha2.Group)(&v1alpha2.GroupVersion.Group),
					Kind:  v1alpha2.Kind("HTTPRoute"),
				}},
				Conditions: []metav1.Condition{
					{
						Type:   string(v1alpha2.ListenerConditionReady),
						Status: metav1.ConditionTrue,
						Reason: string(v1alpha2.ListenerReasonReady),
					},
				},
			}}

			kubernetes.GatewayStatusMustHaveListeners(t, s.Client, gwNN, listeners, 60)
		})
	},
}
