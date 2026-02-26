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
	"k8s.io/apimachinery/pkg/types"

	v1 "sigs.k8s.io/gateway-api/apis/v1"
	"sigs.k8s.io/gateway-api/conformance/utils/kubernetes"
	"sigs.k8s.io/gateway-api/conformance/utils/suite"
	"sigs.k8s.io/gateway-api/pkg/features"
)

func init() {
	ConformanceTests = append(ConformanceTests, TLSRouteInvalidNoMatchingListener)
}

var TLSRouteInvalidNoMatchingListener = suite.ConformanceTest{
	ShortName:   "TLSRouteInvalidNoMatchingListener",
	Description: "A TLSRoute should set Accepted=False when attaching to a Gateway with no compatible TLS listener",
	Features: []features.FeatureName{
		features.SupportGateway,
		features.SupportTLSRoute,
	},
	Manifests: []string{"tests/tlsroute-invalid-no-matching-listener.yaml"},
	Test: func(t *testing.T, suite *suite.ConformanceTestSuite) {
		ns := "gateway-conformance-infra"

		routeNotAllowedProtocolHTTPNN := types.NamespacedName{Name: "tlsroute-not-allowed-protocol-http", Namespace: ns}
		routeNotAllowedProtocolHTTPSNN := types.NamespacedName{Name: "tlsroute-not-allowed-protocol-https", Namespace: ns}
		routeNoMatchingSectionNN := types.NamespacedName{Name: "tlsroute-no-matching-section-name", Namespace: ns}

		gwTLSPassthroughOnlyNN := types.NamespacedName{Name: "gateway-tlsroute-tls-passthrough-only", Namespace: ns}
		gwHTTPOnlyNN := types.NamespacedName{Name: "gateway-tlsroute-http-only", Namespace: ns}
		gwHTTPSOnlyNN := types.NamespacedName{Name: "gateway-tlsroute-https-only", Namespace: ns}

		// This test creates an additional Gateway in the gateway-conformance-infra
		// namespace so we have to wait for it to be ready.
		kubernetes.NamespacesMustBeReady(t, suite.Client, suite.TimeoutConfig, []string{ns})

		acceptedCondNoMatchingParent := metav1.Condition{
			Type:   string(v1.RouteConditionAccepted),
			Status: metav1.ConditionFalse,
			Reason: string(v1.RouteReasonNoMatchingParent),
		}
		acceptedCondNotAllowed := metav1.Condition{
			Type:   string(v1.RouteConditionAccepted),
			Status: metav1.ConditionFalse,
			Reason: string(v1.RouteReasonNotAllowedByListeners),
		}
		t.Run("TLSRoute rejected when listener protocol is HTTP", func(t *testing.T) {
			kubernetes.TLSRouteMustHaveCondition(t, suite.Client, suite.TimeoutConfig, routeNotAllowedProtocolHTTPNN, gwHTTPOnlyNN, acceptedCondNotAllowed)
		})
		t.Run("TLSRoute rejected when listener protocol is HTTPS", func(t *testing.T) {
			kubernetes.TLSRouteMustHaveCondition(t, suite.Client, suite.TimeoutConfig, routeNotAllowedProtocolHTTPSNN, gwHTTPSOnlyNN, acceptedCondNotAllowed)
		})
		t.Run("TLSRoute rejected when sectionName not found", func(t *testing.T) {
			kubernetes.TLSRouteMustHaveCondition(t, suite.Client, suite.TimeoutConfig, routeNoMatchingSectionNN, gwTLSPassthroughOnlyNN, acceptedCondNoMatchingParent)
		})
		t.Run("TLSRoute (HTTP listener) should not have Parents accepted", func(t *testing.T) {
			kubernetes.TLSRouteMustHaveNoAcceptedParents(t, suite.Client, suite.TimeoutConfig, routeNotAllowedProtocolHTTPNN)
		})
		t.Run("TLSRoute (HTTPS listener) should not have Parents accepted", func(t *testing.T) {
			kubernetes.TLSRouteMustHaveNoAcceptedParents(t, suite.Client, suite.TimeoutConfig, routeNotAllowedProtocolHTTPSNN)
		})
		t.Run("TLSRoute (wrong sectionName) should not have Parents accepted", func(t *testing.T) {
			kubernetes.TLSRouteMustHaveNoAcceptedParents(t, suite.Client, suite.TimeoutConfig, routeNoMatchingSectionNN)
		})
		t.Run("Gateway HTTP-only should have 0 Routes attached", func(t *testing.T) {
			kubernetes.GatewayMustHaveZeroRoutes(t, suite.Client, suite.TimeoutConfig, gwHTTPOnlyNN)
		})
		t.Run("Gateway HTTPS-only should have 0 Routes attached", func(t *testing.T) {
			kubernetes.GatewayMustHaveZeroRoutes(t, suite.Client, suite.TimeoutConfig, gwHTTPSOnlyNN)
		})
	},
}
