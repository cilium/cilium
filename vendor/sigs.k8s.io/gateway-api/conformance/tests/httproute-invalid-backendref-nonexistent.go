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
	"sigs.k8s.io/gateway-api/conformance/utils/http"
	"sigs.k8s.io/gateway-api/conformance/utils/kubernetes"
	"sigs.k8s.io/gateway-api/conformance/utils/suite"
)

func init() {
	ConformanceTests = append(ConformanceTests, HTTPRouteInvalidNonExistentBackendRef)
}

var HTTPRouteInvalidNonExistentBackendRef = suite.ConformanceTest{
	ShortName:   "HTTPRouteInvalidNonExistentBackendRef",
	Description: "A single HTTPRoute in the gateway-conformance-infra namespace should set a ResolvedRefs status False with reason BackendNotFound and return 500 when binding to a Gateway in the same namespace if the route has a BackendRef Service that does not exist",
	Manifests:   []string{"tests/httproute-invalid-backendref-nonexistent.yaml"},
	Test: func(t *testing.T, suite *suite.ConformanceTestSuite) {
		routeNN := types.NamespacedName{Name: "invalid-nonexistent-backend-ref", Namespace: "gateway-conformance-infra"}
		gwNN := types.NamespacedName{Name: "same-namespace", Namespace: "gateway-conformance-infra"}

		// Gateway and Route must be Accepted.
		gwAddr := kubernetes.GatewayAndHTTPRoutesMustBeReady(t, suite.Client, suite.ControllerName, kubernetes.NewGatewayRef(gwNN), routeNN)

		t.Run("HTTPRoute with only a nonexistent BackendRef has a ResolvedRefs Condition with status False and Reason BackendNotFound", func(t *testing.T) {
			resolvedRefsCond := metav1.Condition{
				Type:   string(v1alpha2.RouteConditionResolvedRefs),
				Status: metav1.ConditionFalse,
				Reason: string(v1alpha2.RouteReasonBackendNotFound),
			}

			kubernetes.HTTPRouteMustHaveCondition(t, suite.Client, routeNN, gwNN, resolvedRefsCond, 60)
		})

		t.Run("HTTP Request to invalid nonexistent backend receive a 500", func(t *testing.T) {
			http.MakeRequestAndExpectEventuallyConsistentResponse(t, suite.RoundTripper, gwAddr, http.ExpectedResponse{
				Request: http.Request{
					Method: "GET",
					Path:   "/",
				},
				StatusCode: 500,
			})
		})

	},
}
