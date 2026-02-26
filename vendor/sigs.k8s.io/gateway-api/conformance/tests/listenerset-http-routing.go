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

	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"

	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
	"sigs.k8s.io/gateway-api/conformance/utils/http"
	"sigs.k8s.io/gateway-api/conformance/utils/kubernetes"
	"sigs.k8s.io/gateway-api/conformance/utils/suite"
	"sigs.k8s.io/gateway-api/pkg/features"
)

func init() {
	ConformanceTests = append(ConformanceTests, ListenerSetHTTPRouting)
}

var ListenerSetHTTPRouting = suite.ConformanceTest{
	ShortName:   "ListenerSetHTTPRouting",
	Description: "HTTP Routing works as expected with ListenerSets",
	Features: []features.FeatureName{
		features.SupportGateway,
		features.SupportListenerSet,
		features.SupportHTTPRoute,
	},
	Manifests: []string{
		"tests/listenerset-http-routing.yaml",
	},
	Test: func(t *testing.T, suite *suite.ConformanceTestSuite) {
		ns := "gateway-conformance-infra"
		kubernetes.NamespacesMustBeReady(t, suite.Client, suite.TimeoutConfig, []string{ns})

		gwRoutes := []types.NamespacedName{
			{Name: "attaches-to-all-listeners", Namespace: ns},
			{Name: "gateway-route", Namespace: ns},
			{Name: "gateway-section-route", Namespace: ns},
		}
		gwNN := types.NamespacedName{Name: "gateway-with-listener-sets-http-routing", Namespace: ns}
		gwAddr := kubernetes.GatewayAndHTTPRoutesMustBeAccepted(t, suite.Client, suite.TimeoutConfig, suite.ControllerName, kubernetes.NewGatewayRef(gwNN, "gateway-listener"), gwRoutes...)
		kubernetes.GatewayMustHaveAttachedListeners(t, suite.Client, suite.TimeoutConfig, gwNN, 2)

		// listener-set-http-routing-1
		lsRoutes := []types.NamespacedName{
			{Name: "attaches-to-all-listeners", Namespace: ns},
			{Name: "listener-set-http-routing-1-route", Namespace: ns},
			{Name: "listener-set-http-routing-1-section-route", Namespace: ns},
		}
		listenerSetGK := schema.GroupKind{
			Group: gatewayv1.GroupVersion.Group,
			Kind:  "ListenerSet",
		}
		lsNN := types.NamespacedName{Name: "listener-set-http-routing-1", Namespace: ns}
		kubernetes.RoutesAndParentMustBeAccepted(t, suite.Client, suite.TimeoutConfig, suite.ControllerName, kubernetes.NewResourceRef(listenerSetGK, lsNN), &gatewayv1.HTTPRoute{}, lsRoutes...)
		kubernetes.ListenerSetStatusMustHaveListeners(t, suite.Client, suite.TimeoutConfig, lsNN, []gatewayv1.ListenerEntryStatus{
			{
				Name:           "listener-set-http-routing-1-listener-1",
				SupportedKinds: generateSupportedRouteKinds(),
				// This attaches to attaches-to-all-listeners, listener-set-http-routing-1-route, listener-set-http-routing-1-section-route
				AttachedRoutes: 3,
				Conditions:     generateAcceptedListenerConditions(),
			},
			{
				Name:           "listener-set-http-routing-1-listener-2",
				SupportedKinds: generateSupportedRouteKinds(),
				// This attaches to attaches-to-all-listeners, listener-set-http-routing-1-route
				AttachedRoutes: 2,
				Conditions:     generateAcceptedListenerConditions(),
			},
		})

		// listener-set-http-routing-2
		lsRoutes = []types.NamespacedName{
			{Name: "attaches-to-all-listeners", Namespace: ns},
			{Name: "listener-set-http-routing-2-route", Namespace: ns},
		}
		lsNN = types.NamespacedName{Name: "listener-set-http-routing-2", Namespace: ns}
		kubernetes.RoutesAndParentMustBeAccepted(t, suite.Client, suite.TimeoutConfig, suite.ControllerName, kubernetes.NewResourceRef(listenerSetGK, lsNN), &gatewayv1.HTTPRoute{}, lsRoutes...)
		kubernetes.ListenerSetStatusMustHaveListeners(t, suite.Client, suite.TimeoutConfig, lsNN, []gatewayv1.ListenerEntryStatus{
			{
				Name:           "listener-set-http-routing-2-listener-1",
				SupportedKinds: generateSupportedRouteKinds(),
				// This attaches to attaches-to-all-listeners, listener-set-http-routing-2-route
				AttachedRoutes: 2,
				Conditions:     generateAcceptedListenerConditions(),
			},
			{
				Name:           "listener-set-http-routing-2-listener-2",
				SupportedKinds: generateSupportedRouteKinds(),
				// This attaches to attaches-to-all-listeners, listener-set-http-routing-2-route
				AttachedRoutes: 2,
				Conditions:     generateAcceptedListenerConditions(),
			},
		})

		testCases := []http.ExpectedResponse{
			// Requests to the route attached to all resources should succeed
			{
				Request:   http.Request{Host: "gateway-listener-1.com", Path: "/route"},
				Backend:   "infra-backend-v1",
				Namespace: ns,
			},
			{
				Request:   http.Request{Host: "gateway-listener-2.com", Path: "/route"},
				Backend:   "infra-backend-v1",
				Namespace: ns,
			},
			{
				Request:   http.Request{Host: "listener-set-http-routing-1-listener-1.com", Path: "/route"},
				Backend:   "infra-backend-v1",
				Namespace: ns,
			},
			{
				Request:   http.Request{Host: "listener-set-http-routing-1-listener-2.com", Path: "/route"},
				Backend:   "infra-backend-v1",
				Namespace: ns,
			},
			{
				Request:   http.Request{Host: "listener-set-http-routing-2-listener-1.com", Path: "/route"},
				Backend:   "infra-backend-v1",
				Namespace: ns,
			},
			{
				Request:   http.Request{Host: "listener-set-http-routing-2-listener-2.com", Path: "/route"},
				Backend:   "infra-backend-v1",
				Namespace: ns,
			},
			// Requests to the gateway-route should only succeed on gateway listeners
			{
				Request:   http.Request{Host: "gateway-listener-1.com", Path: "/gateway-route"},
				Backend:   "infra-backend-v2",
				Namespace: ns,
			},
			{
				Request:   http.Request{Host: "gateway-listener-2.com", Path: "/gateway-route"},
				Backend:   "infra-backend-v2",
				Namespace: ns,
			},
			{
				Request:  http.Request{Host: "listener-set-http-routing-1-listener-1.com", Path: "/gateway-route"},
				Response: http.Response{StatusCode: 404},
			},
			{
				Request:  http.Request{Host: "listener-set-http-routing-1-listener-2.com", Path: "/gateway-route"},
				Response: http.Response{StatusCode: 404},
			},
			{
				Request:  http.Request{Host: "listener-set-http-routing-2-listener-1.com", Path: "/gateway-route"},
				Response: http.Response{StatusCode: 404},
			},
			{
				Request:  http.Request{Host: "listener-set-http-routing-2-listener-2.com", Path: "/gateway-route"},
				Response: http.Response{StatusCode: 404},
			},
			// Requests to the gateway-section-route should only succeed on gateway-listener-1
			{
				Request:   http.Request{Host: "gateway-listener-1.com", Path: "/gateway-section-route"},
				Backend:   "infra-backend-v3",
				Namespace: ns,
			},
			{
				Request:  http.Request{Host: "gateway-listener-2.com", Path: "/gateway-section-route"},
				Response: http.Response{StatusCode: 404},
			},
			{
				Request:  http.Request{Host: "listener-set-http-routing-1-listener-1.com", Path: "/gateway-section-route"},
				Response: http.Response{StatusCode: 404},
			},
			{
				Request:  http.Request{Host: "listener-set-http-routing-1-listener-2.com", Path: "/gateway-section-route"},
				Response: http.Response{StatusCode: 404},
			},
			{
				Request:  http.Request{Host: "listener-set-http-routing-2-listener-1.com", Path: "/gateway-section-route"},
				Response: http.Response{StatusCode: 404},
			},
			{
				Request:  http.Request{Host: "listener-set-http-routing-2-listener-2.com", Path: "/gateway-section-route"},
				Response: http.Response{StatusCode: 404},
			},
			// Requests to the listener-set-http-routing-1-route should only succeed on listener-set-http-routing-1 listeners
			{
				Request:  http.Request{Host: "gateway-listener-1.com", Path: "/listener-set-http-routing-1-route"},
				Response: http.Response{StatusCode: 404},
			},
			{
				Request:  http.Request{Host: "gateway-listener-2.com", Path: "/listener-set-http-routing-1-route"},
				Response: http.Response{StatusCode: 404},
			},
			{
				Request:   http.Request{Host: "listener-set-http-routing-1-listener-1.com", Path: "/listener-set-http-routing-1-route"},
				Backend:   "infra-backend-v2",
				Namespace: ns,
			},
			{
				Request:   http.Request{Host: "listener-set-http-routing-1-listener-2.com", Path: "/listener-set-http-routing-1-route"},
				Backend:   "infra-backend-v2",
				Namespace: ns,
			},
			{
				Request:  http.Request{Host: "listener-set-http-routing-2-listener-1.com", Path: "/listener-set-http-routing-1-route"},
				Response: http.Response{StatusCode: 404},
			},
			{
				Request:  http.Request{Host: "listener-set-http-routing-2-listener-2.com", Path: "/listener-set-http-routing-1-route"},
				Response: http.Response{StatusCode: 404},
			},
			// Requests to the listener-set-http-routing-1-section-route should only succeed on listener-set-http-routing-1-listener-1
			{
				Request:  http.Request{Host: "gateway-listener-1.com", Path: "/listener-set-http-routing-1-section-route"},
				Response: http.Response{StatusCode: 404},
			},
			{
				Request:  http.Request{Host: "gateway-listener-2.com", Path: "/listener-set-http-routing-1-section-route"},
				Response: http.Response{StatusCode: 404},
			},
			{
				Request:   http.Request{Host: "listener-set-http-routing-1-listener-1.com", Path: "/listener-set-http-routing-1-section-route"},
				Backend:   "infra-backend-v3",
				Namespace: ns,
			},
			{
				Request:  http.Request{Host: "listener-set-http-routing-1-listener-2.com", Path: "/listener-set-http-routing-1-section-route"},
				Response: http.Response{StatusCode: 404},
			},
			{
				Request:  http.Request{Host: "listener-set-http-routing-2-listener-1.com", Path: "/listener-set-http-routing-1-section-route"},
				Response: http.Response{StatusCode: 404},
			},
			{
				Request:  http.Request{Host: "listener-set-http-routing-2-listener-2.com", Path: "/listener-set-http-routing-1-section-route"},
				Response: http.Response{StatusCode: 404},
			},
			// Requests to the listener-set-http-routing-2-route should only succeed on listener-set-http-routing-2 listeners
			{
				Request:  http.Request{Host: "gateway-listener-1.com", Path: "/listener-set-http-routing-2-route"},
				Response: http.Response{StatusCode: 404},
			},
			{
				Request:  http.Request{Host: "gateway-listener-2.com", Path: "/listener-set-http-routing-2-route"},
				Response: http.Response{StatusCode: 404},
			},
			{
				Request:  http.Request{Host: "listener-set-http-routing-1-listener-1.com", Path: "/listener-set-http-routing-2-route"},
				Response: http.Response{StatusCode: 404},
			},
			{
				Request:  http.Request{Host: "listener-set-http-routing-1-listener-2.com", Path: "/listener-set-http-routing-2-route"},
				Response: http.Response{StatusCode: 404},
			},
			{
				Request:   http.Request{Host: "listener-set-http-routing-2-listener-1.com", Path: "/listener-set-http-routing-2-route"},
				Backend:   "infra-backend-v2",
				Namespace: ns,
			},
			{
				Request:   http.Request{Host: "listener-set-http-routing-2-listener-2.com", Path: "/listener-set-http-routing-2-route"},
				Backend:   "infra-backend-v2",
				Namespace: ns,
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

func generateSupportedRouteKinds() []gatewayv1.RouteGroupKind {
	return []gatewayv1.RouteGroupKind{{
		Group: (*gatewayv1.Group)(&gatewayv1.GroupVersion.Group),
		Kind:  gatewayv1.Kind("HTTPRoute"),
	}, {
		Group: (*gatewayv1.Group)(&gatewayv1.GroupVersion.Group),
		Kind:  gatewayv1.Kind("GRPCRoute"),
	}}
}
