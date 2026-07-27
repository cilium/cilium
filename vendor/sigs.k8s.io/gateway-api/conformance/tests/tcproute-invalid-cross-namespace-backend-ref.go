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
	ConformanceTests = append(ConformanceTests, TCPRouteInvalidCrossNamespaceBackendRef)
}

var TCPRouteInvalidCrossNamespaceBackendRef = confsuite.ConformanceTest{
	ShortName:   "TCPRouteInvalidCrossNamespaceBackendRef",
	Description: "A TCPRoute in the gateway-conformance-infra namespace with a backendRef in the gateway-conformance-web-backend namespace and no matching ReferenceGrant should set ResolvedRefs=False with reason RefNotPermitted.",
	Manifests:   []string{"tests/tcproute-invalid-cross-namespace-backend-ref.yaml"},
	Features: []features.FeatureName{
		features.SupportGateway,
		features.SupportTCPRoute,
		features.SupportReferenceGrant,
	},
	Provisional: true,
	Test: func(t *testing.T, suite *confsuite.ConformanceTestSuite) {
		ns := confsuite.InfrastructureNamespace
		routeNN := types.NamespacedName{Name: "tcp-invalid-cross-namespace-backend-ref", Namespace: ns}
		gwNN := types.NamespacedName{Name: "tcp-invalid-cross-namespace-backend-ref-gateway", Namespace: ns}

		// The test creates an additional Gateway in the gateway-conformance-infra
		// namespace so we have to wait for it to be ready.
		kubernetes.NamespacesMustBeReady(t, suite.Client, suite.TimeoutConfig,
			[]string{ns, confsuite.WebBackendNamespace})

		// The TCPRoute should still be Accepted on its parent; only the
		// backend resolution is denied.
		kubernetes.GatewayAndTCPRoutesMustBeAccepted(t, suite.Client, suite.TimeoutConfig, suite.ControllerName,
			kubernetes.NewGatewayRef(gwNN, "tcp"), routeNN)

		t.Run("TCPRoute with a cross-namespace backendRef and no ReferenceGrant has ResolvedRefs=False with reason RefNotPermitted", func(t *testing.T) {
			resolvedRefsCond := metav1.Condition{
				Type:   string(v1.RouteConditionResolvedRefs),
				Status: metav1.ConditionFalse,
				Reason: string(v1.RouteReasonRefNotPermitted),
			}
			kubernetes.TCPRouteMustHaveCondition(t, suite.Client, suite.TimeoutConfig, routeNN, gwNN, resolvedRefsCond)
		})
	},
}
