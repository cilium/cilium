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
	ConformanceTests = append(ConformanceTests, GatewayListenerUnsupportedProtocol)
}

var GatewayListenerUnsupportedProtocol = suite.ConformanceTest{
	ShortName:   "GatewayListenerUnsupportedProtocol",
	Description: "A Gateway should set the Accepted condition to False with reason UnsupportedProtocol on listeners whose protocol is not supported. The Gateway itself should only be Accepted if at least one of its listeners is accepted.",
	Features: []features.FeatureName{
		features.SupportGateway,
	},
	Manifests: []string{"tests/gateway-invalid-listeners-unsupported-protocol.yaml"},
	Parallel:  true,
	Test: func(t *testing.T, s *suite.ConformanceTestSuite) {
		t.Run("Gateway with no accepted listeners should not be accepted and the listener should have the Accepted condition set to False with reason UnsupportedProtocol", func(t *testing.T) {
			t.Parallel()

			gwNN := types.NamespacedName{Name: "gateway-only-unsupported-protocols", Namespace: suite.InfrastructureNamespace}

			kubernetes.GatewayMustHaveLatestConditions(t, s.Client, s.TimeoutConfig, gwNN)
			kubernetes.GatewayMustHaveCondition(t, s.Client, s.TimeoutConfig, gwNN, metav1.Condition{
				Type:   string(gatewayv1.GatewayConditionAccepted),
				Status: metav1.ConditionFalse,
				Reason: string(gatewayv1.GatewayReasonListenersNotValid),
			})

			kubernetes.GatewayStatusMustHaveListeners(t, s.Client, s.TimeoutConfig, gwNN, []gatewayv1.ListenerStatus{
				{
					Name:           gatewayv1.SectionName("invalid"),
					SupportedKinds: []gatewayv1.RouteGroupKind{},
					Conditions: []metav1.Condition{{
						Type:   string(gatewayv1.ListenerConditionAccepted),
						Status: metav1.ConditionFalse,
						Reason: string(gatewayv1.ListenerReasonUnsupportedProtocol),
					}},
					AttachedRoutes: 0,
				},
			})
		})
		t.Run("Gateway with at least one accepted listeners should be accepted and the listeners should have the Accepted condition set accordingly", func(t *testing.T) {
			t.Parallel()

			gwNN := types.NamespacedName{Name: "gateway-supported-and-unsupported-protocols", Namespace: suite.InfrastructureNamespace}

			kubernetes.GatewayMustHaveLatestConditions(t, s.Client, s.TimeoutConfig, gwNN)
			kubernetes.GatewayMustHaveCondition(t, s.Client, s.TimeoutConfig, gwNN, metav1.Condition{
				Type:   string(gatewayv1.GatewayConditionAccepted),
				Status: metav1.ConditionTrue,
				Reason: string(gatewayv1.GatewayReasonListenersNotValid),
			})

			kubernetes.GatewayStatusMustHaveListeners(t, s.Client, s.TimeoutConfig, gwNN, []gatewayv1.ListenerStatus{
				{
					Name: gatewayv1.SectionName("http"),
					SupportedKinds: []gatewayv1.RouteGroupKind{{
						Group: (*gatewayv1.Group)(&gatewayv1.GroupVersion.Group),
						Kind:  gatewayv1.Kind("HTTPRoute"),
					}},
					Conditions: []metav1.Condition{{
						Type:   string(gatewayv1.ListenerConditionAccepted),
						Status: metav1.ConditionTrue,
						Reason: string(gatewayv1.ListenerReasonAccepted),
					}},
					AttachedRoutes: 0,
				},
				{
					Name:           gatewayv1.SectionName("invalid"),
					SupportedKinds: []gatewayv1.RouteGroupKind{},
					Conditions: []metav1.Condition{{
						Type:   string(gatewayv1.ListenerConditionAccepted),
						Status: metav1.ConditionFalse,
						Reason: string(gatewayv1.ListenerReasonUnsupportedProtocol),
					}},
					AttachedRoutes: 0,
				},
			})
		})
	},
}
