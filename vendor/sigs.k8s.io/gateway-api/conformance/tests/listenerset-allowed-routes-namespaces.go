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

	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"

	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
	"sigs.k8s.io/gateway-api/conformance/utils/http"
	"sigs.k8s.io/gateway-api/conformance/utils/kubernetes"
	"sigs.k8s.io/gateway-api/conformance/utils/suite"
	"sigs.k8s.io/gateway-api/pkg/features"
)

func init() {
	ConformanceTests = append(ConformanceTests, ListenerSetAllowedRoutesNamespaces)
}

var ListenerSetAllowedRoutesNamespaces = suite.ConformanceTest{
	ShortName:   "ListenerSetAllowedRoutesNamespaces",
	Description: "ListenerSet listeners allow routes from the specified namespace",
	Features: []features.FeatureName{
		features.SupportGateway,
		features.SupportListenerSet,
		features.SupportHTTPRoute,
		features.SupportReferenceGrant,
	},
	Manifests: []string{
		"tests/listenerset-allowed-routes-namespaces.yaml",
	},
	Test: func(t *testing.T, suite *suite.ConformanceTestSuite) {
		ns := "gateway-conformance-infra"
		kubernetes.NamespacesMustBeReady(t, suite.Client, suite.TimeoutConfig, []string{ns})

		// Verify the gateway is accepted
		gwNN := types.NamespacedName{Name: "gateway-with-listener-sets-test-allowed-routes", Namespace: ns}
		gwAddr, err := kubernetes.WaitForGatewayAddress(t, suite.Client, suite.TimeoutConfig, kubernetes.NewGatewayRef(gwNN, "gateway-listener"))
		require.NoErrorf(t, err, "timed out waiting for Gateway address to be assigned")
		kubernetes.GatewayMustHaveCondition(t, suite.Client, suite.TimeoutConfig, gwNN, metav1.Condition{
			Type:   string(gatewayv1.GatewayConditionAccepted),
			Status: metav1.ConditionTrue,
		})
		kubernetes.GatewayMustHaveAttachedListeners(t, suite.Client, suite.TimeoutConfig, gwNN, 1)

		// Verify the accepted listenerSet has the appropriate conditions
		routes := []types.NamespacedName{
			{Name: "route-in-same-namespace", Namespace: ns},
			{Name: "route-in-selected-namespace", Namespace: "gateway-api-routes-allowed-ns"},
			{Name: "route-not-in-selected-namespace", Namespace: "gateway-api-routes-not-allowed-ns"},
		}
		listenerSetGK := schema.GroupKind{
			Group: gatewayv1.GroupVersion.Group,
			Kind:  "ListenerSet",
		}
		lsNN := types.NamespacedName{Name: "listenerset-test-allowed-routes-namespaces", Namespace: ns}
		listenerSetRef := kubernetes.NewResourceRef(listenerSetGK, lsNN)
		kubernetes.RoutesAndParentMustBeAccepted(t, suite.Client, suite.TimeoutConfig, suite.ControllerName, listenerSetRef, &gatewayv1.HTTPRoute{}, routes...)
		kubernetes.ListenerSetStatusMustHaveListeners(t, suite.Client, suite.TimeoutConfig, lsNN, []gatewayv1.ListenerEntryStatus{
			{
				Name:           "listener-set-listener-allowed-routes-all",
				SupportedKinds: generateSupportedRouteKinds(),
				// This attaches to route-in-same-namespace, route-in-selected-namespace, route-not-in-selected-namespace
				AttachedRoutes: 3,
				Conditions:     generateAcceptedListenerConditions(),
			},
			{
				Name:           "listener-set-listener-allowed-routes-same",
				SupportedKinds: generateSupportedRouteKinds(),
				// This attaches to route-in-same-namespace
				AttachedRoutes: 1,
				Conditions:     generateAcceptedListenerConditions(),
			},
			{
				Name:           "listener-set-listener-allowed-routes-selector",
				SupportedKinds: generateSupportedRouteKinds(),
				// This attaches to route-in-selected-namespace
				AttachedRoutes: 1,
				Conditions:     generateAcceptedListenerConditions(),
			},
		})

		testCases := []http.ExpectedResponse{
			// Requests to all the routes on `listener-set-listener-allowed-routes-all` should succeed
			{
				Request:   http.Request{Host: "listener-set-listener-allowed-routes-all.com", Path: "/route-in-same-namespace"},
				Backend:   "infra-backend-v1",
				Namespace: ns,
			},
			{
				Request:   http.Request{Host: "listener-set-listener-allowed-routes-all.com", Path: "/route-in-selected-namespace"},
				Backend:   "infra-backend-v2",
				Namespace: ns,
			},
			{
				Request:   http.Request{Host: "listener-set-listener-allowed-routes-all.com", Path: "/route-not-in-selected-namespace"},
				Backend:   "infra-backend-v3",
				Namespace: ns,
			},
			// Requests only to the route in the same namespace on `listener-set-listener-allowed-routes-same` should succeed
			{
				Request:   http.Request{Host: "listener-set-listener-allowed-routes-same.com", Path: "/route-in-same-namespace"},
				Backend:   "infra-backend-v1",
				Namespace: ns,
			},
			{
				Request:  http.Request{Host: "listener-set-listener-allowed-routes-same.com", Path: "/route-in-selected-namespace"},
				Response: http.Response{StatusCode: 404},
			},
			{
				Request:  http.Request{Host: "listener-set-listener-allowed-routes-same.com", Path: "/route-not-in-selected-namespace"},
				Response: http.Response{StatusCode: 404},
			},
			// Requests only to the route in the selected namespace on `listener-set-listener-allowed-routes-selector` should succeed
			{
				Request:  http.Request{Host: "listener-set-listener-allowed-routes-selector.com", Path: "/route-in-same-namespace"},
				Response: http.Response{StatusCode: 404},
			},
			{
				Request:   http.Request{Host: "listener-set-listener-allowed-routes-selector.com", Path: "/route-in-selected-namespace"},
				Backend:   "infra-backend-v2",
				Namespace: ns,
			},
			{
				Request:  http.Request{Host: "listener-set-listener-allowed-routes-selector.com", Path: "/route-not-in-selected-namespace"},
				Response: http.Response{StatusCode: 404},
			},
		}

		for i := range testCases {
			// Declare tc here to avoid loop variable
			// reuse issues across parallel tests.
			tc := testCases[i]
			t.Run(tc.GetTestCaseName(i), func(t *testing.T) {
				t.Parallel()
				http.MakeRequestAndExpectEventuallyConsistentResponse(t, suite.RoundTripper, suite.TimeoutConfig, gwAddr, tc)
			})
		}
	},
}
