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
	ConformanceTests = append(ConformanceTests, HTTPRouteInvalidCrossNamespaceBackendRef)
}

var HTTPRouteInvalidCrossNamespaceBackendRef = suite.ConformanceTest{
	ShortName:   "HTTPRouteInvalidCrossNamespaceBackendRef",
	Description: "A single HTTPRoute in the gateway-conformance-infra namespace should set a ResolvedRefs status False with reason RefNotPermitted when attempting to bind to a Gateway in the same namespace if the route has a BackendRef Service in the gateway-conformance-web-backend namespace and a ReferenceGrant granting permission to route to that Service does not exist",
	Features:    []suite.SupportedFeature{suite.SupportReferenceGrant},
	Manifests:   []string{"tests/httproute-invalid-cross-namespace-backend-ref.yaml"},
	Test: func(t *testing.T, suite *suite.ConformanceTestSuite) {
		routeNN := types.NamespacedName{Name: "invalid-cross-namespace-backend-ref", Namespace: "gateway-conformance-infra"}
		gwNN := types.NamespacedName{Name: "same-namespace", Namespace: "gateway-conformance-infra"}

		// The Route must be Attached.
		gwAddr := kubernetes.GatewayAndHTTPRoutesMustBeAccepted(t, suite.Client, suite.TimeoutConfig, suite.ControllerName, kubernetes.NewGatewayRef(gwNN), routeNN)

		t.Run("HTTPRoute with a cross-namespace BackendRef and no ReferenceGrant has a ResolvedRefs Condition with status False and Reason RefNotPermitted", func(t *testing.T) {

			resolvedRefsCond := metav1.Condition{
				Type:   string(v1beta1.RouteConditionResolvedRefs),
				Status: metav1.ConditionFalse,
				Reason: string(v1beta1.RouteReasonRefNotPermitted),
			}

			kubernetes.HTTPRouteMustHaveCondition(t, suite.Client, suite.TimeoutConfig, routeNN, gwNN, resolvedRefsCond)
		})

		t.Run("HTTP Request to invalid cross-namespace backend must receive a 500", func(t *testing.T) {
			http.MakeRequestAndExpectEventuallyConsistentResponse(t, suite.RoundTripper, suite.TimeoutConfig, gwAddr, http.ExpectedResponse{
				Request: http.Request{
					Method: "GET",
					Path:   "/",
				},
				Response: http.Response{StatusCode: 500},
			})
		})

	},
}
