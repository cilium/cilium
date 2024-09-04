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
	ConformanceTests = append(ConformanceTests, GatewayWithAttachedRoutes, GatewayWithAttachedRoutesWithPort8080)
}

var GatewayWithAttachedRoutes = suite.ConformanceTest{
	ShortName:   "GatewayWithAttachedRoutes",
	Description: "A Gateway in the gateway-conformance-infra namespace should be attached to routes.",
	Features: []features.FeatureName{
		features.SupportGateway,
		features.SupportHTTPRoute,
	},
	Manifests: []string{"tests/gateway-with-attached-routes.yaml"},
	Test: func(t *testing.T, s *suite.ConformanceTestSuite) {
		t.Run("Gateway listener should have one valid http routes attached", func(t *testing.T) {
			gwNN := types.NamespacedName{Name: "gateway-with-one-attached-route", Namespace: "gateway-conformance-infra"}
			listeners := []v1.ListenerStatus{{
				Name: v1.SectionName("http"),
				SupportedKinds: []v1.RouteGroupKind{{
					Group: (*v1.Group)(&v1.GroupVersion.Group),
					Kind:  v1.Kind("HTTPRoute"),
				}},
				Conditions: []metav1.Condition{
					{
						Type:   string(v1.ListenerConditionAccepted),
						Status: metav1.ConditionTrue,
						Reason: "", // any reason
					},
					{
						Type:   string(v1.ListenerConditionResolvedRefs),
						Status: metav1.ConditionTrue,
						Reason: "", // any reason
					},
				},
				AttachedRoutes: 1,
			}}

			kubernetes.GatewayStatusMustHaveListeners(t, s.Client, s.TimeoutConfig, gwNN, listeners)
		})

		t.Run("Gateway listener should have two valid http routes attached", func(t *testing.T) {
			gwNN := types.NamespacedName{Name: "gateway-with-two-attached-routes", Namespace: "gateway-conformance-infra"}
			listeners := []v1.ListenerStatus{{
				Name: v1.SectionName("http"),
				SupportedKinds: []v1.RouteGroupKind{{
					Group: (*v1.Group)(&v1.GroupVersion.Group),
					Kind:  v1.Kind("HTTPRoute"),
				}},
				Conditions: []metav1.Condition{
					{
						Type:   string(v1.ListenerConditionAccepted),
						Status: metav1.ConditionTrue,
						Reason: "", // any reason
					},
					{
						Type:   string(v1.ListenerConditionResolvedRefs),
						Status: metav1.ConditionTrue,
						Reason: "", // any reason
					},
				},
				AttachedRoutes: 2,
			}}

			kubernetes.GatewayStatusMustHaveListeners(t, s.Client, s.TimeoutConfig, gwNN, listeners)
		})

		t.Run("Gateway listener should have AttachedRoutes set even when Gateway has unresolved refs", func(t *testing.T) {
			gwNN := types.NamespacedName{Name: "unresolved-gateway-with-one-attached-unresolved-route", Namespace: "gateway-conformance-infra"}
			listeners := []v1.ListenerStatus{{
				Name: v1.SectionName("tls"),
				SupportedKinds: []v1.RouteGroupKind{{
					Group: (*v1.Group)(&v1.GroupVersion.Group),
					Kind:  v1.Kind("HTTPRoute"),
				}},
				Conditions: []metav1.Condition{
					{
						Type:   string(v1.ListenerConditionProgrammed),
						Status: metav1.ConditionFalse,
						Reason: "", // any reason
					},
					{
						Type:   string(v1.ListenerConditionResolvedRefs),
						Status: metav1.ConditionFalse,
						Reason: "", // any reason
					},
				},
				AttachedRoutes: 1,
			}}

			kubernetes.GatewayStatusMustHaveListeners(t, s.Client, s.TimeoutConfig, gwNN, listeners)

			hrouteNN := types.NamespacedName{Name: "http-route-4", Namespace: "gateway-conformance-infra"}
			unresolved := metav1.Condition{
				Type:   string(v1.RouteConditionResolvedRefs),
				Status: metav1.ConditionFalse,
				Reason: "", // any reason
			}

			kubernetes.HTTPRouteMustHaveCondition(t, s.Client, s.TimeoutConfig, hrouteNN, gwNN, unresolved)
		})
	},
}

var GatewayWithAttachedRoutesWithPort8080 = suite.ConformanceTest{
	ShortName:   "GatewayWithAttachedRoutesWithPort8080",
	Description: "A Gateway in the gateway-conformance-infra namespace should be attached to routes.",
	Features: []features.FeatureName{
		features.SupportGateway,
		features.SupportGatewayPort8080,
		features.SupportHTTPRoute,
	},
	Manifests: []string{"tests/gateway-with-attached-routes-with-port-8080.yaml"},
	Test: func(t *testing.T, s *suite.ConformanceTestSuite) {
		t.Run("Gateway listener should have attached route by specifying the sectionName", func(t *testing.T) {
			gwNN := types.NamespacedName{Name: "gateway-with-two-listeners-and-one-attached-route", Namespace: "gateway-conformance-infra"}
			listeners := []v1.ListenerStatus{
				{
					Name: v1.SectionName("http-unattached"),
					SupportedKinds: []v1.RouteGroupKind{{
						Group: (*v1.Group)(&v1.GroupVersion.Group),
						Kind:  v1.Kind("HTTPRoute"),
					}},
					Conditions: []metav1.Condition{
						{
							Type:   string(v1.ListenerConditionAccepted),
							Status: metav1.ConditionTrue,
							Reason: "", // any reason
						},
						{
							Type:   string(v1.ListenerConditionResolvedRefs),
							Status: metav1.ConditionTrue,
							Reason: "", // any reason
						},
					},
					AttachedRoutes: 0,
				},
				{
					Name: v1.SectionName("http"),
					SupportedKinds: []v1.RouteGroupKind{{
						Group: (*v1.Group)(&v1.GroupVersion.Group),
						Kind:  v1.Kind("HTTPRoute"),
					}},
					Conditions: []metav1.Condition{
						{
							Type:   string(v1.ListenerConditionAccepted),
							Status: metav1.ConditionTrue,
							Reason: "", // any reason
						},
						{
							Type:   string(v1.ListenerConditionResolvedRefs),
							Status: metav1.ConditionTrue,
							Reason: "", // any reason
						},
					},
					AttachedRoutes: 1,
				},
			}

			kubernetes.GatewayStatusMustHaveListeners(t, s.Client, s.TimeoutConfig, gwNN, listeners)
		})
	},
}
