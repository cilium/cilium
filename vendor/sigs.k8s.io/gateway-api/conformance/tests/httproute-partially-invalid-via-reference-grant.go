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
	ConformanceTests = append(ConformanceTests, HTTPRoutePartiallyInvalidViaInvalidReferenceGrant)
}

var HTTPRoutePartiallyInvalidViaInvalidReferenceGrant = suite.ConformanceTest{
	ShortName:   "HTTPRoutePartiallyInvalidViaInvalidReferenceGrant",
	Description: "A single HTTPRoute in the gateway-conformance-infra namespace should attach to a Gateway in the same namespace if the route has a backendRef Service in the gateway-conformance-app-backend namespace and a ReferenceGrant exists but does not grant permission to route to that specific Service",
	Features:    []suite.SupportedFeature{suite.SupportReferenceGrant},
	Manifests:   []string{"tests/httproute-partially-invalid-via-reference-grant.yaml"},
	Test: func(t *testing.T, s *suite.ConformanceTestSuite) {
		routeNN := types.NamespacedName{Name: "invalid-reference-grant", Namespace: "gateway-conformance-infra"}
		gwNN := types.NamespacedName{Name: "same-namespace", Namespace: "gateway-conformance-infra"}

		// Route and Gateway must be Attached.
		gwAddr := kubernetes.GatewayAndHTTPRoutesMustBeAccepted(t, s.Client, s.TimeoutConfig, s.ControllerName, kubernetes.NewGatewayRef(gwNN), routeNN)

		t.Run("HTTPRoute with BackendRef in another namespace and no ReferenceGrant covering the Service has a ResolvedRefs Condition with status False and Reason RefNotPermitted", func(t *testing.T) {

			resolvedRefsCond := metav1.Condition{
				Type:   string(v1beta1.RouteConditionResolvedRefs),
				Status: metav1.ConditionFalse,
				Reason: string(v1beta1.RouteReasonRefNotPermitted),
			}

			kubernetes.HTTPRouteMustHaveCondition(t, s.Client, s.TimeoutConfig, routeNN, gwNN, resolvedRefsCond)
		})

		t.Run("HTTP Request to invalid backend with missing referenceGrant should receive a 500", func(t *testing.T) {
			http.MakeRequestAndExpectEventuallyConsistentResponse(t, s.RoundTripper, s.TimeoutConfig, gwAddr, http.ExpectedResponse{
				Request: http.Request{
					Method: "GET",
					Path:   "/v2",
				},
				Response: http.Response{StatusCode: 500},
			})
		})

		t.Run("HTTP Request to valid sibling backend should succeed", func(t *testing.T) {
			http.MakeRequestAndExpectEventuallyConsistentResponse(t, s.RoundTripper, s.TimeoutConfig, gwAddr, http.ExpectedResponse{
				Request: http.Request{
					Method: "GET",
					Path:   "/",
				},
				Response:  http.Response{StatusCode: 200},
				Backend:   "app-backend-v1",
				Namespace: "gateway-conformance-app-backend",
			})
		})

	},
}
