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
	"sigs.k8s.io/gateway-api/conformance/utils/tls"
	"sigs.k8s.io/gateway-api/pkg/features"
)

func init() {
	ConformanceTests = append(ConformanceTests, TLSRouteInvalidBackendRefNonexistent)
}

var TLSRouteInvalidBackendRefNonexistent = suite.ConformanceTest{
	ShortName:   "TLSRouteInvalidBackendRefNonexistent",
	Description: "A single TLSRoute in the gateway-conformance-infra namespace has a ResolvedRefs status False with reason BackendNotFound when binding to a Gateway in the same namespace, if the route has a BackendRef Service that does not exist",
	Features: []features.FeatureName{
		features.SupportGateway,
		features.SupportTLSRoute,
	},
	Manifests: []string{"tests/tlsroute-invalid-backendref-nonexistent.yaml"},
	Test: func(t *testing.T, suite *suite.ConformanceTestSuite) {
		ns := "gateway-conformance-infra"
		routeNN := types.NamespacedName{Name: "invalid-backend-ref-nonexistent", Namespace: ns}
		gwNN := types.NamespacedName{Name: "gateway-tlsroute-invalid-backend-ref-nonexistent", Namespace: ns}

		// This test creates an additional Gateway in the gateway-conformance-infra
		// namespace so we have to wait for it to be ready.
		kubernetes.NamespacesMustBeReady(t, suite.Client, suite.TimeoutConfig, []string{ns})

		// Both the Gateway and the Route are Accepted.
		gwAddr, hostnames := kubernetes.GatewayAndTLSRoutesMustBeAccepted(t, suite.Client, suite.TimeoutConfig, suite.ControllerName, kubernetes.NewGatewayRef(gwNN), routeNN)

		// The Route must have a ResolvedRefs Condition with a InvalidKind Reason.
		t.Run("TLSRoute with only a nonexistent BackendRef has a ResolvedRefs Condition with status False and Reason BackendNotFound", func(t *testing.T) {
			resolvedRefsCond := metav1.Condition{
				Type:   string(v1.RouteConditionResolvedRefs),
				Status: metav1.ConditionFalse,
				Reason: string(v1.RouteReasonBackendNotFound),
			}

			kubernetes.TLSRouteMustHaveCondition(t, suite.Client, suite.TimeoutConfig, routeNN, gwNN, resolvedRefsCond)
		})

		t.Run("TLS connection to nonexistent backend should be rejected", func(t *testing.T) {
			serverStr := string(hostnames[0])
			tls.MakeTLSConnectionAndExpectEventuallyConnectionRejection(t, suite.TimeoutConfig, gwAddr, serverStr)
		})
	},
}
