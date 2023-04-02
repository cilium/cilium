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

	"k8s.io/apimachinery/pkg/types"

	"sigs.k8s.io/gateway-api/conformance/utils/kubernetes"
	"sigs.k8s.io/gateway-api/conformance/utils/suite"
)

func init() {
	ConformanceTests = append(ConformanceTests, HTTPRouteDisallowedKind)
}

var HTTPRouteDisallowedKind = suite.ConformanceTest{
	ShortName:   "HTTPRouteDisallowedKind",
	Description: "A single HTTPRoute in the gateway-conformance-infra namespace should fail to attach to a Listener that does not allow the HTTPRoute kind",
	Features:    []suite.SupportedFeature{suite.SupportTLSRoute},
	Manifests:   []string{"tests/httproute-disallowed-kind.yaml"},
	Test: func(t *testing.T, suite *suite.ConformanceTestSuite) {
		// This test creates an additional Gateway in the gateway-conformance-infra
		// namespace so we have to wait for it to be ready.
		kubernetes.NamespacesMustBeAccepted(t, suite.Client, suite.TimeoutConfig, []string{"gateway-conformance-infra"})

		routeName := types.NamespacedName{Name: "disallowed-kind", Namespace: "gateway-conformance-infra"}
		gwName := types.NamespacedName{Name: "tlsroutes-only", Namespace: "gateway-conformance-infra"}

		t.Run("Route should not have Parents set in status", func(t *testing.T) {
			kubernetes.HTTPRouteMustHaveNoAcceptedParents(t, suite.Client, suite.TimeoutConfig, routeName)
		})
		t.Run("Gateway should have 0 Routes attached", func(t *testing.T) {
			kubernetes.GatewayMustHaveZeroRoutes(t, suite.Client, suite.TimeoutConfig, gwName)
		})
	},
}
