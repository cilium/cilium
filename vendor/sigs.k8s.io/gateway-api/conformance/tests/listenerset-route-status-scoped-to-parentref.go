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
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"

	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
	"sigs.k8s.io/gateway-api/conformance/utils/kubernetes"
	confsuite "sigs.k8s.io/gateway-api/conformance/utils/suite"
	"sigs.k8s.io/gateway-api/pkg/features"
)

func init() {
	ConformanceTests = append(ConformanceTests, ListenerSetRouteStatusScopedToParentRef)
}

var ListenerSetRouteStatusScopedToParentRef = confsuite.ConformanceTest{
	ShortName:   "ListenerSetRouteStatusScopedToParentRef",
	Description: "A Route's status.parents must contain entries only for its explicitly declared parentRefs",
	Features: []features.FeatureName{
		features.SupportGateway,
		features.SupportListenerSet,
		features.SupportHTTPRoute,
	},
	Manifests: []string{
		"tests/listenerset-route-status-scoped-to-parentref.yaml",
	},
	Test: func(t *testing.T, suite *confsuite.ConformanceTestSuite) {
		ns := confsuite.InfrastructureNamespace
		kubernetes.NamespacesMustBeReady(t, suite.Client, suite.TimeoutConfig, []string{ns})

		gwNN := types.NamespacedName{Name: "gateway-parentref", Namespace: ns}
		kubernetes.GatewayMustHaveCondition(t, suite.Client, suite.TimeoutConfig, gwNN, metav1.Condition{
			Type:   string(gatewayv1.GatewayConditionAccepted),
			Status: metav1.ConditionTrue,
		})
		kubernetes.GatewayMustHaveAttachedListeners(t, suite.Client, suite.TimeoutConfig, gwNN, 1)

		listenerSetGK := schema.GroupKind{
			Group: gatewayv1.GroupVersion.Group,
			Kind:  "ListenerSet",
		}
		lsNN := types.NamespacedName{Name: "listenerset-parentref", Namespace: ns}
		lsRef := kubernetes.NewResourceRef(listenerSetGK, lsNN)

		kubernetes.ListenerSetStatusMustHaveListeners(t, suite.Client, suite.TimeoutConfig, lsNN, []gatewayv1.ListenerEntryStatus{
			{
				Name:           "listenerset-parentref-listener",
				SupportedKinds: generateSupportedRouteKinds(),
				AttachedRoutes: 1,
				Conditions:     generateAcceptedListenerConditions(),
			},
		})

		t.Run("Gateway-only parentRef", func(t *testing.T) {
			gwOnlyRouteNN := types.NamespacedName{Name: "route-parentref-gwonly", Namespace: ns}
			kubernetes.HTTPRouteMustHaveCondition(t, suite.Client, suite.TimeoutConfig, gwOnlyRouteNN, gwNN, metav1.Condition{
				Type:   string(gatewayv1.RouteConditionAccepted),
				Status: metav1.ConditionTrue,
			})
			kubernetes.HTTPRouteMustHaveParents(t, suite.Client, suite.TimeoutConfig, gwOnlyRouteNN,
				[]gatewayv1.RouteParentStatus{
					{
						ParentRef: gatewayv1.ParentReference{
							Group:     new(gatewayv1.Group(gatewayv1.GroupVersion.Group)),
							Kind:      new(gatewayv1.Kind("Gateway")),
							Name:      "gateway-parentref",
							Namespace: new(gatewayv1.Namespace(ns)),
						},
						ControllerName: gatewayv1.GatewayController(suite.ControllerName),
						Conditions: []metav1.Condition{
							{
								Type:   string(gatewayv1.RouteConditionAccepted),
								Status: metav1.ConditionTrue,
							},
						},
					},
				},
				true,
			)
		})

		t.Run("ListenerSet-only parentRef", func(t *testing.T) {
			lsOnlyRouteNN := types.NamespacedName{Name: "route-parentref-lsonly", Namespace: ns}
			kubernetes.RoutesAndParentMustBeAccepted(t, suite.Client, suite.TimeoutConfig, suite.ControllerName, lsRef, &gatewayv1.HTTPRoute{}, lsOnlyRouteNN)
			kubernetes.HTTPRouteMustHaveParents(t, suite.Client, suite.TimeoutConfig, lsOnlyRouteNN,
				[]gatewayv1.RouteParentStatus{
					{
						ParentRef: gatewayv1.ParentReference{
							Group:     new(gatewayv1.Group(gatewayv1.GroupVersion.Group)),
							Kind:      new(gatewayv1.Kind("ListenerSet")),
							Name:      "listenerset-parentref",
							Namespace: new(gatewayv1.Namespace(ns)),
						},
						ControllerName: gatewayv1.GatewayController(suite.ControllerName),
						Conditions: []metav1.Condition{
							{
								Type:   string(gatewayv1.RouteConditionAccepted),
								Status: metav1.ConditionTrue,
							},
						},
					},
				},
				true,
			)
		})
	},
}
