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
	ConformanceTests = append(ConformanceTests, TLSRouteListenerPassthroughSupportedKinds)
}

var TLSRouteListenerPassthroughSupportedKinds = confsuite.ConformanceTest{
	ShortName:   "TLSRouteListenerPassthroughSupportedKinds",
	Description: "A Gateway Listener with TLS mode Passthrough MUST include TLSRoute in SupportedKinds",
	Features: []features.FeatureName{
		features.SupportGateway,
		features.SupportTLSRoute,
	},
	Manifests: []string{"tests/tlsroute-listener-passthrough-supported-kinds.yaml"},
	Test: func(t *testing.T, suite *confsuite.ConformanceTestSuite) {
		gwNN := types.NamespacedName{Name: "gateway-tlsroute-passthrough-supported-kind", Namespace: confsuite.InfrastructureNamespace}

		t.Run("TLS listener should have a false ResolvedRefs condition with reason InvalidRouteKinds for TCPRoute, and TLSRoute must be put in the supportedKinds", func(t *testing.T) {
			listeners := []v1.ListenerStatus{{
				Name: v1.SectionName("tls-passthrough"),
				SupportedKinds: []v1.RouteGroupKind{{
					Group: (*v1.Group)(&v1.GroupVersion.Group),
					Kind:  v1.Kind("TLSRoute"),
				}},
				Conditions: []metav1.Condition{{
					Type:   string(v1.ListenerConditionResolvedRefs),
					Status: metav1.ConditionFalse,
					Reason: string(v1.ListenerReasonInvalidRouteKinds),
				}},
				AttachedRoutes: 0,
			}}
			kubernetes.GatewayStatusMustHaveListeners(t, suite.Client, suite.TimeoutConfig, gwNN, listeners)
		})
	},
}
