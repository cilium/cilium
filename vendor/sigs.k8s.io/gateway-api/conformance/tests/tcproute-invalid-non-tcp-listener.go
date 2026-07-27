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
	confsuite "sigs.k8s.io/gateway-api/conformance/utils/suite"
	"sigs.k8s.io/gateway-api/pkg/features"
)

func init() {
	ConformanceTests = append(ConformanceTests, TCPRouteInvalidNonTCPListener)
}

var TCPRouteInvalidNonTCPListener = confsuite.ConformanceTest{
	ShortName:   "TCPRouteInvalidNonTCPListener",
	Description: "A TCPRoute should set Accepted=False with reason NotAllowedByListeners when attaching to a non-TCP listener via sectionName.",
	Manifests:   []string{"tests/tcproute-invalid-non-tcp-listener.yaml"},
	Features: []features.FeatureName{
		features.SupportGateway,
		features.SupportTCPRoute,
	},
	Provisional: true,
	Test: func(t *testing.T, suite *confsuite.ConformanceTestSuite) {
		ns := confsuite.InfrastructureNamespace
		routeNN := types.NamespacedName{Name: "tcp-route", Namespace: ns}
		gwNN := types.NamespacedName{Name: "tcp-mixed-protocol-gateway", Namespace: ns}

		// This test creates an additional Gateway in the gateway-conformance-infra
		// namespace so we have to wait for it to be ready.
		kubernetes.NamespacesMustBeReady(t, suite.Client, suite.TimeoutConfig, []string{ns})

		t.Run("TCPRoute targeting a listener that has no protocol type TCP must have Accepted=False with reason NotAllowedByListeners", func(t *testing.T) {
			notAllowed := metav1.Condition{
				Type:   string(v1.RouteConditionAccepted),
				Status: metav1.ConditionFalse,
				Reason: string(v1.RouteReasonNotAllowedByListeners),
			}
			kubernetes.TCPRouteMustHaveCondition(t, suite.Client, suite.TimeoutConfig, routeNN, gwNN, notAllowed)
		})

		t.Run("Gateway should have 0 Routes attached", func(t *testing.T) {
			kubernetes.GatewayMustHaveZeroRoutes(t, suite.Client, suite.TimeoutConfig, gwNN)
		})
	},
}
