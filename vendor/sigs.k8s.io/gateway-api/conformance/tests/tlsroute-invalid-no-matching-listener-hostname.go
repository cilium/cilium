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
	ConformanceTests = append(ConformanceTests, TLSRouteInvalidNoMatchingListenerHostname)
}

var TLSRouteInvalidNoMatchingListenerHostname = suite.ConformanceTest{
	ShortName:   "TLSRouteInvalidNoMatchingListenerHostname",
	Description: "A TLSRoute with a hostname that does not match the Gateway listener hostname should set Accepted=False with Reason=NoMatchingListenerHostname",
	Features: []features.FeatureName{
		features.SupportGateway,
		features.SupportTLSRoute,
	},
	Manifests: []string{"tests/tlsroute-invalid-no-matching-listener-hostname.yaml"},
	Test: func(t *testing.T, suite *suite.ConformanceTestSuite) {
		ns := "gateway-conformance-infra"
		route1NN := types.NamespacedName{Name: "tlsroute-hostname-mismatch-1", Namespace: ns}
		route2NN := types.NamespacedName{Name: "tlsroute-hostname-mismatch-2", Namespace: ns}
		exactGwNN := types.NamespacedName{Name: "gateway-tls-exact-hostname", Namespace: ns}
		wildcardGwNN := types.NamespacedName{Name: "gateway-tls-wildcard-hostname", Namespace: ns}
		kubernetes.NamespacesMustBeReady(t, suite.Client, suite.TimeoutConfig, []string{ns})

		acceptedCond := metav1.Condition{
			Type:   string(v1.RouteConditionAccepted),
			Status: metav1.ConditionFalse,
			Reason: string(v1.RouteReasonNoMatchingListenerHostname),
		}

		t.Run("TLSRoute 1 has Accepted=False for exact hostname Gateway", func(t *testing.T) {
			kubernetes.TLSRouteMustHaveCondition(t, suite.Client, suite.TimeoutConfig, route1NN, exactGwNN, acceptedCond)
		})

		t.Run("TLSRoute 2 has Accepted=False for wildcard hostname Gateway", func(t *testing.T) {
			kubernetes.TLSRouteMustHaveCondition(t, suite.Client, suite.TimeoutConfig, route2NN, wildcardGwNN, acceptedCond)
		})

		t.Run("TLSRoute 1 must have no accepted parents", func(t *testing.T) {
			kubernetes.TLSRouteMustHaveNoAcceptedParents(t, suite.Client, suite.TimeoutConfig, route1NN)
		})

		t.Run("TLSRoute 2 must have no accepted parents", func(t *testing.T) {
			kubernetes.TLSRouteMustHaveNoAcceptedParents(t, suite.Client, suite.TimeoutConfig, route2NN)
		})

		t.Run("Exact hostname Gateway must have 0 Routes attached", func(t *testing.T) {
			kubernetes.GatewayMustHaveZeroRoutes(t, suite.Client, suite.TimeoutConfig, exactGwNN)
		})

		t.Run("Wildcard hostname Gateway must have 0 Routes attached", func(t *testing.T) {
			kubernetes.GatewayMustHaveZeroRoutes(t, suite.Client, suite.TimeoutConfig, wildcardGwNN)
		})
	},
}
