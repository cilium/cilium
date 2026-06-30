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

	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"

	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
	"sigs.k8s.io/gateway-api/conformance/utils/http"
	"sigs.k8s.io/gateway-api/conformance/utils/kubernetes"
	confsuite "sigs.k8s.io/gateway-api/conformance/utils/suite"
	"sigs.k8s.io/gateway-api/pkg/features"
)

func init() {
	ConformanceTests = append(ConformanceTests, ListenerSetDualParentRefIndependence)
}

var ListenerSetDualParentRefIndependence = confsuite.ConformanceTest{
	ShortName:   "ListenerSetDualParentRefIndependence",
	Description: "A Route with both Gateway and ListenerSet parentRefs has independently evaluated Accepted conditions for each parentRef",
	Features: []features.FeatureName{
		features.SupportGateway,
		features.SupportListenerSet,
		features.SupportHTTPRoute,
	},
	Manifests: []string{
		"tests/listenerset-dual-parentref-independence.yaml",
	},
	Test: func(t *testing.T, suite *confsuite.ConformanceTestSuite) {
		ns := confsuite.InfrastructureNamespace
		kubernetes.NamespacesMustBeReady(t, suite.Client, suite.TimeoutConfig, []string{ns})

		gwNN := types.NamespacedName{Name: "gateway-dual-parentref", Namespace: ns}
		gwAddr, err := kubernetes.WaitForGatewayAddress(t, suite.Client, suite.TimeoutConfig, kubernetes.NewGatewayRef(gwNN, "gw-dual-parentref-listener"))
		require.NoErrorf(t, err, "timed out waiting for Gateway address to be assigned")
		kubernetes.GatewayMustHaveCondition(t, suite.Client, suite.TimeoutConfig, gwNN, metav1.Condition{
			Type:   string(gatewayv1.GatewayConditionAccepted),
			Status: metav1.ConditionTrue,
		})
		kubernetes.GatewayMustHaveAttachedListeners(t, suite.Client, suite.TimeoutConfig, gwNN, 1)

		listenerSetGK := schema.GroupKind{
			Group: gatewayv1.GroupVersion.Group,
			Kind:  "ListenerSet",
		}
		lsNN := types.NamespacedName{Name: "ls-dual-parentref", Namespace: ns}
		kubernetes.ListenerSetStatusMustHaveListeners(t, suite.Client, suite.TimeoutConfig, lsNN, []gatewayv1.ListenerEntryStatus{
			{
				Name:           "ls-dual-parentref-listener",
				SupportedKinds: generateSupportedRouteKinds(),
				AttachedRoutes: 2,
				Conditions:     generateAcceptedListenerConditions(),
			},
		})

		t.Run("Both parentRefs are Accepted", func(t *testing.T) {
			dualRouteNN := types.NamespacedName{Name: "route-dual-parentref-both", Namespace: ns}
			kubernetes.HTTPRouteMustHaveCondition(t, suite.Client, suite.TimeoutConfig, dualRouteNN, gwNN, metav1.Condition{
				Type:   string(gatewayv1.RouteConditionAccepted),
				Status: metav1.ConditionTrue,
			})
			kubernetes.HTTPRouteMustHaveCondition(t, suite.Client, suite.TimeoutConfig, dualRouteNN, lsNN, metav1.Condition{
				Type:   string(gatewayv1.RouteConditionAccepted),
				Status: metav1.ConditionTrue,
			})

			testCases := []http.ExpectedResponse{
				{
					Request:   http.Request{Host: "gw-dual.com", Path: "/dualboth"},
					Backend:   confsuite.InfraBackendServiceNameV1,
					Namespace: ns,
				},
				{
					Request:   http.Request{Host: "ls-dual.com", Path: "/dualboth"},
					Backend:   confsuite.InfraBackendServiceNameV1,
					Namespace: ns,
				},
			}

			for i := range testCases {
				tc := testCases[i]
				t.Run(tc.GetTestCaseName(i), func(t *testing.T) {
					t.Parallel()
					http.MakeRequestAndExpectEventuallyConsistentResponse(t, suite.RoundTripper, suite.TimeoutConfig, gwAddr, tc)
				})
			}
		})

		t.Run("One of two parentRefs is Accepted", func(t *testing.T) {
			badGWRouteNN := types.NamespacedName{Name: "route-dual-parentref-one", Namespace: ns}
			kubernetes.HTTPRouteMustHaveCondition(t, suite.Client, suite.TimeoutConfig, badGWRouteNN, gwNN, metav1.Condition{
				Type:   string(gatewayv1.RouteConditionAccepted),
				Status: metav1.ConditionFalse,
				Reason: string(gatewayv1.RouteReasonNoMatchingParent),
			})
			kubernetes.HTTPRouteMustHaveCondition(t, suite.Client, suite.TimeoutConfig, badGWRouteNN, lsNN, metav1.Condition{
				Type:   string(gatewayv1.RouteConditionAccepted),
				Status: metav1.ConditionTrue,
			})

			lsRef := kubernetes.NewResourceRef(listenerSetGK, lsNN)
			kubernetes.RoutesAndParentMustBeAccepted(t, suite.Client, suite.TimeoutConfig, suite.ControllerName, lsRef, &gatewayv1.HTTPRoute{},
				types.NamespacedName{Name: "route-dual-parentref-one", Namespace: ns})

			testCases := []http.ExpectedResponse{
				{
					Request:   http.Request{Host: "ls-dual.com", Path: "/dualone"},
					Backend:   confsuite.InfraBackendServiceNameV2,
					Namespace: ns,
				},
				{
					Request:  http.Request{Host: "gw-dual.com", Path: "/dualone"},
					Response: http.Response{StatusCode: 404},
				},
			}

			for i := range testCases {
				tc := testCases[i]
				t.Run(tc.GetTestCaseName(i), func(t *testing.T) {
					t.Parallel()
					http.MakeRequestAndExpectEventuallyConsistentResponse(t, suite.RoundTripper, suite.TimeoutConfig, gwAddr, tc)
				})
			}
		})
	},
}
