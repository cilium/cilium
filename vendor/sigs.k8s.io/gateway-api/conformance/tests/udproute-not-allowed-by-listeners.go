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

	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
	"sigs.k8s.io/gateway-api/conformance/utils/kubernetes"
	confsuite "sigs.k8s.io/gateway-api/conformance/utils/suite"
	"sigs.k8s.io/gateway-api/pkg/features"
)

func init() {
	ConformanceTests = append(ConformanceTests, UDPRouteNotAllowedByListeners)
}

var UDPRouteNotAllowedByListeners = confsuite.ConformanceTest{
	ShortName: "UDPRouteNotAllowedByListeners",
	Description: "A UDPRoute targeting a Gateway listener whose protocol is not UDP must report " +
		"Accepted=False with reason NotAllowedByListeners and must not be attached to the listener.",
	Manifests: []string{"tests/udproute-not-allowed-by-listeners.yaml"},
	Features: []features.FeatureName{
		features.SupportGateway,
		features.SupportUDPRoute,
	},
	Provisional: true,
	Test: func(t *testing.T, suite *confsuite.ConformanceTestSuite) {
		if !suite.SupportedFeatures.Has(features.SupportTLSRoute) {
			return
		}
		ns := confsuite.InfrastructureNamespace
		gwNN := types.NamespacedName{Name: "udproute-tls-only-gateway", Namespace: ns}
		routeNN := types.NamespacedName{Name: "udproute-not-allowed-by-listeners", Namespace: ns}

		// This test creates an additional Gateway in the gateway-conformance-infra
		// namespace so we have to wait for it to be ready.
		kubernetes.NamespacesMustBeReady(t, suite.Client, suite.TimeoutConfig, []string{ns})

		t.Run("UDPRoute should have Accepted=False with reason NotAllowedByListeners", func(t *testing.T) {
			kubernetes.UDPRouteMustHaveCondition(t, suite.Client, suite.TimeoutConfig, routeNN, gwNN, metav1.Condition{
				Type:   string(gatewayv1.RouteConditionAccepted),
				Status: metav1.ConditionFalse,
				Reason: string(gatewayv1.RouteReasonNotAllowedByListeners),
			})
		})

		t.Run("Gateway should have 0 Routes attached on the TLS listener", func(t *testing.T) {
			kubernetes.GatewayMustHaveZeroRoutes(t, suite.Client, suite.TimeoutConfig, gwNN)
		})
	},
}
