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
	v1beta1 "sigs.k8s.io/gateway-api/apis/v1beta1"
	"sigs.k8s.io/gateway-api/conformance/utils/kubernetes"
	confsuite "sigs.k8s.io/gateway-api/conformance/utils/suite"
	"sigs.k8s.io/gateway-api/conformance/utils/tcp"
	"sigs.k8s.io/gateway-api/pkg/features"
)

func init() {
	ConformanceTests = append(ConformanceTests, TCPRouteReferenceGrant)
}

var TCPRouteReferenceGrant = confsuite.ConformanceTest{
	ShortName:   "TCPRouteReferenceGrant",
	Description: "A single TCPRoute in the gateway-conformance-infra namespace, with a backendRef in the gateway-conformance-web-backend namespace, should attach to a Gateway in the gateway-conformance-infra namespace when a ReferenceGrant in the backend namespace permits the reference.",
	Manifests:   []string{"tests/tcproute-reference-grant.yaml"},
	Features: []features.FeatureName{
		features.SupportGateway,
		features.SupportTCPRoute,
		features.SupportReferenceGrant,
	},
	Provisional: true,
	Test: func(t *testing.T, suite *confsuite.ConformanceTestSuite) {
		ns := confsuite.InfrastructureNamespace
		routeNN := types.NamespacedName{Name: "tcp-reference-grant", Namespace: ns}
		gwNN := types.NamespacedName{Name: "tcp-reference-grant-gateway", Namespace: ns}

		// The test creates an additional Gateway in the gateway-conformance-infra
		// namespace so we have to wait for it to be ready.
		kubernetes.NamespacesMustBeReady(t, suite.Client, suite.TimeoutConfig,
			[]string{ns, confsuite.WebBackendNamespace})

		gwAddr := kubernetes.GatewayAndTCPRoutesMustBeAccepted(t, suite.Client, suite.TimeoutConfig, suite.ControllerName,
			kubernetes.NewGatewayRef(gwNN, "tcp"), routeNN)

		t.Run("TCP request should reach the cross-namespace backend", func(t *testing.T) {
			tcp.MakeTCPRequestAndExpectEventuallyValidResponse(t, suite.TimeoutConfig, gwAddr, nil, "", false,
				tcp.ExpectedResponse{
					Backend:   "tcp-reference-grant-backend",
					Namespace: confsuite.WebBackendNamespace,
				})
		})

		// Deleting the ReferenceGrant should revoke permission to reach the
		// cross-namespace backend, transitioning ResolvedRefs to False with
		// reason RefNotPermitted.
		ctx, cancel := context.WithTimeout(context.Background(), suite.TimeoutConfig.DeleteTimeout)
		defer cancel()
		rg := v1.ReferenceGrant{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "tcp-reference-grant",
				Namespace: confsuite.WebBackendNamespace,
			},
		}
		require.NoError(t, suite.Client.Delete(ctx, &rg))

		t.Run("TCPRoute ResolvedRefs becomes False with reason RefNotPermitted after the ReferenceGrant is deleted", func(t *testing.T) {
			resolvedRefsCond := metav1.Condition{
				Type:   string(v1beta1.RouteConditionResolvedRefs),
				Status: metav1.ConditionFalse,
				Reason: string(v1beta1.RouteReasonRefNotPermitted),
			}
			kubernetes.TCPRouteMustHaveCondition(t, suite.Client, suite.TimeoutConfig, routeNN, gwNN, resolvedRefsCond)
		})
	},
}
