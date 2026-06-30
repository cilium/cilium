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
	ConformanceTests = append(ConformanceTests, UDPRouteInvalidCrossNamespaceBackendRef)
}

var UDPRouteInvalidCrossNamespaceBackendRef = confsuite.ConformanceTest{
	ShortName:   "UDPRouteInvalidCrossNamespaceBackendRef",
	Description: "A UDPRoute in the gateway-conformance-infra namespace should set ResolvedRefs=False with reason RefNotPermitted when its backendRef points to a Service in the gateway-conformance-app-backend namespace and no ReferenceGrant grants permission to that Service.",
	Manifests:   []string{"tests/udproute-invalid-cross-namespace-backend-ref.yaml"},
	Features: []features.FeatureName{
		features.SupportGateway,
		features.SupportUDPRoute,
		features.SupportReferenceGrant,
	},
	Provisional: true,
	Test: func(t *testing.T, suite *confsuite.ConformanceTestSuite) {
		ns := confsuite.InfrastructureNamespace
		routeNN := types.NamespacedName{Name: "udp-route-invalid-cross-namespace-backend-ref", Namespace: ns}
		gwNN := types.NamespacedName{Name: "udp-gateway-invalid-cross-namespace-backend-ref", Namespace: ns}

		// The test creates an additional Gateway in the gateway-conformance-infra
		// namespace so we have to wait for it to be ready.
		kubernetes.NamespacesMustBeReady(t, suite.Client, suite.TimeoutConfig, []string{ns})

		// The UDPRoute must still be Accepted by the Gateway even though the
		// backend reference is not permitted.
		kubernetes.GatewayAndUDPRoutesMustBeAccepted(t, suite.Client, suite.TimeoutConfig, suite.ControllerName, kubernetes.NewGatewayRef(gwNN), routeNN)

		t.Run("UDPRoute with a cross-namespace BackendRef and no ReferenceGrant has a ResolvedRefs Condition with status False and Reason RefNotPermitted", func(t *testing.T) {
			resolvedRefsCond := metav1.Condition{
				Type:   string(v1.RouteConditionResolvedRefs),
				Status: metav1.ConditionFalse,
				Reason: string(v1.RouteReasonRefNotPermitted),
			}
			kubernetes.UDPRouteMustHaveCondition(t, suite.Client, suite.TimeoutConfig, routeNN, gwNN, resolvedRefsCond)
		})
	},
}
