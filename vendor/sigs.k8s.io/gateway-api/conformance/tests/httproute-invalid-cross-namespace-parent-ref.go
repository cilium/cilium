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
	ConformanceTests = append(ConformanceTests, HTTPRouteInvalidCrossNamespaceParentRef)
}

var HTTPRouteInvalidCrossNamespaceParentRef = suite.ConformanceTest{
	ShortName:   "HTTPRouteInvalidCrossNamespaceParentRef",
	Description: "A single HTTPRoute in the gateway-conformance-web-backend namespace should fail to attach to a Gateway in another namespace that it is not allowed to",
	Features: []features.FeatureName{
		features.SupportGateway,
		features.SupportHTTPRoute,
	},
	Manifests: []string{"tests/httproute-invalid-cross-namespace-parent-ref.yaml"},
	Test: func(t *testing.T, suite *suite.ConformanceTestSuite) {
		gwNN := types.NamespacedName{Name: "same-namespace", Namespace: "gateway-conformance-infra"}
		routeNN := types.NamespacedName{Name: "invalid-cross-namespace-parent-ref", Namespace: "gateway-conformance-web-backend"}
		kubernetes.HTTPRouteMustHaveResolvedRefsConditionsTrue(t, suite.Client, suite.TimeoutConfig, routeNN, gwNN)

		// When running conformance tests, implementations are expected to have visibility across all namespaces, and
		// must be setting this condition on routes that are not allowed. However, outside of conformance testing,
		// it's also valid for implementations to run in modes where they only have access to a limited subset of
		// namespaces, in which case they are not obligated to populate this condition on routes they cannot access.
		t.Run("HTTPRoute should have an Accepted: false condition with reason NotAllowedByListeners", func(t *testing.T) {
			acceptedCond := metav1.Condition{
				Type:   string(v1.RouteConditionAccepted),
				Status: metav1.ConditionFalse,
				Reason: string(v1.RouteReasonNotAllowedByListeners),
			}

			kubernetes.HTTPRouteMustHaveCondition(t, suite.Client, suite.TimeoutConfig, routeNN, gwNN, acceptedCond)
		})

		t.Run("Route should not have Parents set in status", func(t *testing.T) {
			kubernetes.HTTPRouteMustHaveNoAcceptedParents(t, suite.Client, suite.TimeoutConfig, routeNN)
		})

		t.Run("Gateway should have 0 Routes attached", func(t *testing.T) {
			kubernetes.GatewayMustHaveZeroRoutes(t, suite.Client, suite.TimeoutConfig, gwNN)
		})
	},
}
