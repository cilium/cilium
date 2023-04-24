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
	"sigs.k8s.io/gateway-api/conformance/utils/kubernetes"
	"sigs.k8s.io/gateway-api/conformance/utils/suite"
)

func init() {
	ConformanceTests = append(ConformanceTests, HTTPRouteInvalidParentRefNotMatchingListenerPort)
}

var HTTPRouteInvalidParentRefNotMatchingListenerPort = suite.ConformanceTest{
	ShortName:   "HTTPRouteInvalidParentRefNotMatchingListenerPort",
	Description: "A single HTTPRoute in the gateway-conformance-infra namespace should set the Accepted status to False with reason NoMatchingParent when attempting to bind to a Gateway that does not have a matching ListenerPort.",
	Features:    []suite.SupportedFeature{suite.SupportRouteDestinationPortMatching},
	Manifests:   []string{"tests/httproute-invalid-parentref-not-matching-listener-port.yaml"},
	Test: func(t *testing.T, suite *suite.ConformanceTestSuite) {
		routeNN := types.NamespacedName{Name: "httproute-listener-not-matching-route-port", Namespace: "gateway-conformance-infra"}
		gwNN := types.NamespacedName{Name: "same-namespace", Namespace: "gateway-conformance-infra"}

		// The Route must have an Accepted Condition with a NoMatchingParent Reason.
		t.Run("HTTPRoute with no matching port in ParentRef has an Accepted Condition with status False and Reason NoMatchingParent", func(t *testing.T) {
			resolvedRefsCond := metav1.Condition{
				Type:   string(v1beta1.RouteConditionAccepted),
				Status: metav1.ConditionFalse,
				Reason: string(v1beta1.RouteReasonNoMatchingParent),
			}

			kubernetes.HTTPRouteMustHaveCondition(t, suite.Client, suite.TimeoutConfig, routeNN, gwNN, resolvedRefsCond)
		})

		t.Run("Route should not have Parents accepted in status", func(t *testing.T) {
			kubernetes.HTTPRouteMustHaveNoAcceptedParents(t, suite.Client, suite.TimeoutConfig, routeNN)
		})

		t.Run("Gateway should have 0 Routes attached", func(t *testing.T) {
			kubernetes.GatewayMustHaveZeroRoutes(t, suite.Client, suite.TimeoutConfig, gwNN)
		})
	},
}
