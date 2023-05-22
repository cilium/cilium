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

	"sigs.k8s.io/gateway-api/apis/v1beta1"
	"sigs.k8s.io/gateway-api/conformance/utils/http"
	"sigs.k8s.io/gateway-api/conformance/utils/kubernetes"
	"sigs.k8s.io/gateway-api/conformance/utils/suite"
)

func init() {
	ConformanceTests = append(ConformanceTests, HTTPRouteHostnameIntersection)
}

var HTTPRouteHostnameIntersection = suite.ConformanceTest{
	ShortName:   "HTTPRouteHostnameIntersection",
	Description: "HTTPRoutes should attach to listeners only if they have intersecting hostnames, and should accept requests only for the intersecting hostnames",
	Manifests:   []string{"tests/httproute-hostname-intersection.yaml"},
	Test: func(t *testing.T, suite *suite.ConformanceTestSuite) {
		ns := "gateway-conformance-infra"
		gwNN := types.NamespacedName{Name: "httproute-hostname-intersection", Namespace: ns}

		// This test creates an additional Gateway in the gateway-conformance-infra
		// namespace so we have to wait for it to be ready.
		kubernetes.NamespacesMustBeAccepted(t, suite.Client, suite.TimeoutConfig, []string{ns})

		t.Run("HTTPRoutes that do intersect with listener hostnames", func(t *testing.T) {
			routes := []types.NamespacedName{
				{Namespace: ns, Name: "specific-host-matches-listener-specific-host"},
				{Namespace: ns, Name: "specific-host-matches-listener-wildcard-host"},
				{Namespace: ns, Name: "wildcard-host-matches-listener-specific-host"},
				{Namespace: ns, Name: "wildcard-host-matches-listener-wildcard-host"},
			}
			gwAddr := kubernetes.GatewayAndHTTPRoutesMustBeAccepted(t, suite.Client, suite.TimeoutConfig, suite.ControllerName, kubernetes.NewGatewayRef(gwNN), routes...)

			var testCases []http.ExpectedResponse

			// Test cases for HTTPRoute "specific-host-matches-listener-specific-host".
			testCases = append(testCases,
				http.ExpectedResponse{
					Request:   http.Request{Host: "very.specific.com", Path: "/s1"},
					Backend:   "infra-backend-v1",
					Namespace: ns,
				},
				http.ExpectedResponse{
					Request:  http.Request{Host: "non.matching.com", Path: "/s1"},
					Response: http.Response{StatusCode: 404},
				},
				http.ExpectedResponse{
					Request:  http.Request{Host: "foo.nonmatchingwildcard.io", Path: "/s1"},
					Response: http.Response{StatusCode: 404},
				},
				http.ExpectedResponse{
					Request:  http.Request{Host: "foo.wildcard.io", Path: "/s1"},
					Response: http.Response{StatusCode: 404},
				},
				http.ExpectedResponse{
					Request:  http.Request{Host: "very.specific.com", Path: "/non-matching-prefix"},
					Response: http.Response{StatusCode: 404},
				},
			)

			//  Test cases for HTTPRoute "specific-host-matches-listener-wildcard-host".
			testCases = append(testCases,
				http.ExpectedResponse{
					Request:   http.Request{Host: "foo.wildcard.io", Path: "/s2"},
					Backend:   "infra-backend-v2",
					Namespace: ns,
				},
				http.ExpectedResponse{
					Request:   http.Request{Host: "bar.wildcard.io", Path: "/s2"},
					Backend:   "infra-backend-v2",
					Namespace: ns,
				},
				http.ExpectedResponse{
					Request:   http.Request{Host: "foo.bar.wildcard.io", Path: "/s2"},
					Backend:   "infra-backend-v2",
					Namespace: ns,
				},
				http.ExpectedResponse{
					Request:  http.Request{Host: "non.matching.com", Path: "/s2"},
					Response: http.Response{StatusCode: 404},
				},
				http.ExpectedResponse{
					Request:  http.Request{Host: "wildcard.io", Path: "/s2"},
					Response: http.Response{StatusCode: 404},
				},

				http.ExpectedResponse{
					Request:  http.Request{Host: "very.specific.com", Path: "/s2"},
					Response: http.Response{StatusCode: 404},
				},
				http.ExpectedResponse{
					Request:  http.Request{Host: "foo.wildcard.io", Path: "/non-matching-prefix"},
					Response: http.Response{StatusCode: 404},
				},
			)

			//  Test cases for HTTPRoute "wildcard-host-matches-listener-specific-host".
			testCases = append(testCases,
				http.ExpectedResponse{
					Request:   http.Request{Host: "very.specific.com", Path: "/s3"},
					Backend:   "infra-backend-v3",
					Namespace: ns,
				},
				http.ExpectedResponse{
					Request:  http.Request{Host: "non.matching.com", Path: "/s3"},
					Response: http.Response{StatusCode: 404},
				},
				http.ExpectedResponse{
					Request:  http.Request{Host: "foo.specific.com", Path: "/s3"},
					Response: http.Response{StatusCode: 404},
				},
				http.ExpectedResponse{
					Request:  http.Request{Host: "foo.wildcard.io", Path: "/s3"},
					Response: http.Response{StatusCode: 404},
				},
				http.ExpectedResponse{
					Request:  http.Request{Host: "very.specific.com", Path: "/non-matching-prefix"},
					Response: http.Response{StatusCode: 404},
				},
			)

			//  Test cases for HTTPRoute "wildcard-host-matches-listener-wildcard-host".
			testCases = append(testCases,
				http.ExpectedResponse{
					Request:   http.Request{Host: "foo.anotherwildcard.io", Path: "/s4"},
					Backend:   "infra-backend-v1",
					Namespace: ns,
				},
				http.ExpectedResponse{
					Request:   http.Request{Host: "bar.anotherwildcard.io", Path: "/s4"},
					Backend:   "infra-backend-v1",
					Namespace: ns,
				},
				http.ExpectedResponse{
					Request:   http.Request{Host: "foo.bar.anotherwildcard.io", Path: "/s4"},
					Backend:   "infra-backend-v1",
					Namespace: ns,
				},
				http.ExpectedResponse{
					Request:  http.Request{Host: "anotherwildcard.io", Path: "/s4"},
					Response: http.Response{StatusCode: 404},
				},

				http.ExpectedResponse{
					Request:  http.Request{Host: "foo.wildcard.io", Path: "/s4"},
					Response: http.Response{StatusCode: 404},
				},
				http.ExpectedResponse{
					Request:  http.Request{Host: "very.specific.com", Path: "/s4"},
					Response: http.Response{StatusCode: 404},
				},
				http.ExpectedResponse{
					Request:  http.Request{Host: "foo.anotherwildcard.io", Path: "/non-matching-prefix"},
					Response: http.Response{StatusCode: 404},
				},
			)

			for i := range testCases {
				// Declare tc here to avoid loop variable
				// reuse issues across parallel tests.
				tc := testCases[i]
				t.Run(tc.GetTestCaseName(i), func(t *testing.T) {
					t.Parallel()
					http.MakeRequestAndExpectEventuallyConsistentResponse(t, suite.RoundTripper, suite.TimeoutConfig, gwAddr, tc)
				})
			}
		})

		t.Run("HTTPRoutes that do not intersect with listener hostnames", func(t *testing.T) {
			gwAddr := kubernetes.GatewayAndHTTPRoutesMustBeAccepted(t, suite.Client, suite.TimeoutConfig, suite.ControllerName, kubernetes.NewGatewayRef(gwNN))
			routeNN := types.NamespacedName{Namespace: ns, Name: "no-intersecting-hosts"}

			parents := []v1beta1.RouteParentStatus{{
				ParentRef:      parentRefTo(gwNN),
				ControllerName: v1beta1.GatewayController(suite.ControllerName),
				Conditions: []metav1.Condition{
					{
						Type:   string(v1beta1.RouteConditionAccepted),
						Status: metav1.ConditionFalse,
						Reason: string(v1beta1.RouteReasonNoMatchingListenerHostname),
					},
				},
			}}

			kubernetes.HTTPRouteMustHaveParents(t, suite.Client, suite.TimeoutConfig, routeNN, parents, true)

			testCases := []http.ExpectedResponse{
				{
					Request:  http.Request{Host: "specific.but.wrong.com", Path: "/s5"},
					Response: http.Response{StatusCode: 404},
				},
				{
					Request:  http.Request{Host: "wildcard.io", Path: "/s5"},
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
		})
	},
}

func parentRefTo(gateway types.NamespacedName) v1beta1.ParentReference {
	var (
		group     = v1beta1.Group(v1beta1.GroupName)
		kind      = v1beta1.Kind("Gateway")
		namespace = v1beta1.Namespace(gateway.Namespace)
		name      = v1beta1.ObjectName(gateway.Name)
	)

	return v1beta1.ParentReference{
		Group:     &group,
		Kind:      &kind,
		Namespace: &namespace,
		Name:      name,
	}
}
