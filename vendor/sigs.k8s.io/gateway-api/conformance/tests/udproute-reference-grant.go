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
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	v1 "sigs.k8s.io/gateway-api/apis/v1"
	"sigs.k8s.io/gateway-api/conformance/utils/kubernetes"
	confsuite "sigs.k8s.io/gateway-api/conformance/utils/suite"
	"sigs.k8s.io/gateway-api/conformance/utils/udp"
	"sigs.k8s.io/gateway-api/pkg/features"
)

func init() {
	ConformanceTests = append(ConformanceTests, UDPRouteReferenceGrant)
}

var UDPRouteReferenceGrant = confsuite.ConformanceTest{
	ShortName:   "UDPRouteReferenceGrant",
	Description: "A UDPRoute in the gateway-conformance-infra namespace, with a backendRef in the gateway-conformance-app-backend namespace, should attach to the Gateway and forward UDP traffic to the backend while a ReferenceGrant permits the cross-namespace reference.",
	Manifests:   []string{"tests/udproute-reference-grant.yaml"},
	Features: []features.FeatureName{
		features.SupportGateway,
		features.SupportUDPRoute,
		features.SupportReferenceGrant,
	},
	Provisional: true,
	Test: func(t *testing.T, suite *confsuite.ConformanceTestSuite) {
		ns := confsuite.InfrastructureNamespace
		routeNN := types.NamespacedName{Name: "udp-route-reference-grant", Namespace: ns}
		gwNN := types.NamespacedName{Name: "udp-gateway-reference-grant", Namespace: ns}

		// The test creates an additional Gateway in the gateway-conformance-infra
		// namespace so we have to wait for it to be ready.
		kubernetes.NamespacesMustBeReady(t, suite.Client, suite.TimeoutConfig, []string{ns})

		gwAddr := kubernetes.GatewayAndUDPRoutesMustBeAccepted(t, suite.Client, suite.TimeoutConfig, suite.ControllerName, kubernetes.NewGatewayRef(gwNN), routeNN)

		t.Run("UDPRoute with cross-namespace backendRef and a permitting ReferenceGrant has ResolvedRefs=True", func(t *testing.T) {
			resolvedRefsCond := metav1.Condition{
				Type:   string(v1.RouteConditionResolvedRefs),
				Status: metav1.ConditionTrue,
				Reason: string(v1.RouteReasonResolvedRefs),
			}
			kubernetes.UDPRouteMustHaveCondition(t, suite.Client, suite.TimeoutConfig, routeNN, gwNN, resolvedRefsCond)
		})

		t.Run("UDP echo request reaches the cross-namespace backend while the ReferenceGrant exists", func(t *testing.T) {
			udp.ExpectEchoResponse(t, suite.TimeoutConfig.DefaultTestTimeout, gwAddr)
		})

		ctx, cancel := context.WithTimeout(context.Background(), suite.TimeoutConfig.DeleteTimeout)
		defer cancel()
		rg := v1.ReferenceGrant{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "udp-reference-grant",
				Namespace: confsuite.AppBackendNamespace,
			},
		}
		require.NoError(t, suite.Client.Delete(ctx, &rg))

		t.Run("UDPRoute has ResolvedRefs=False with reason RefNotPermitted after deleting the ReferenceGrant", func(t *testing.T) {
			resolvedRefsCond := metav1.Condition{
				Type:   string(v1.RouteConditionResolvedRefs),
				Status: metav1.ConditionFalse,
				Reason: string(v1.RouteReasonRefNotPermitted),
			}
			kubernetes.UDPRouteMustHaveCondition(t, suite.Client, suite.TimeoutConfig, routeNN, gwNN, resolvedRefsCond)
		})
	},
}
