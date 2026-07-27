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
	"sigs.k8s.io/gateway-api/conformance/utils/udp"
	"sigs.k8s.io/gateway-api/pkg/features"
)

func init() {
	ConformanceTests = append(ConformanceTests, UDPRouteParentRefAttachAllListeners)
}

var UDPRouteParentRefAttachAllListeners = confsuite.ConformanceTest{
	ShortName:   "UDPRouteParentRefAttachAllListeners",
	Description: "A UDPRoute whose parentRef sets neither `port` nor `sectionName` attaches to every UDP listener on the Gateway, and traffic to each listener reaches the configured backend.",
	Manifests:   []string{"tests/udproute-parentref-attach-all-listeners.yaml"},
	Features: []features.FeatureName{
		features.SupportGateway,
		features.SupportUDPRoute,
	},
	Provisional: true,
	Test: func(t *testing.T, suite *confsuite.ConformanceTestSuite) {
		ns := confsuite.InfrastructureNamespace
		gwNN := types.NamespacedName{Name: "udp-attach-all-listeners-gateway", Namespace: ns}
		routeNN := types.NamespacedName{Name: "udp-route-attach-all", Namespace: ns}
		const backend = "udp-echo-attach-all"

		// The test creates an additional Gateway in the gateway-conformance-infra
		// namespace so we have to wait for it to be ready.
		kubernetes.NamespacesMustBeReady(t, suite.Client, suite.TimeoutConfig, []string{ns})

		group := v1.Group(v1.GroupVersion.Group)
		kind := v1.Kind("Gateway")
		gwName := v1.ObjectName(gwNN.Name)
		gwNS := v1.Namespace(ns)
		acceptedParent := v1.RouteParentStatus{
			ParentRef: v1.ParentReference{
				Group:     &group,
				Kind:      &kind,
				Name:      gwName,
				Namespace: &gwNS,
			},
			ControllerName: v1.GatewayController(suite.ControllerName),
			Conditions: []metav1.Condition{{
				Type:   string(v1.RouteConditionAccepted),
				Status: metav1.ConditionTrue,
				Reason: string(v1.RouteReasonAccepted),
			}},
		}

		t.Run("UDPRoute is accepted by the Gateway", func(t *testing.T) {
			kubernetes.UDPRouteMustHaveParents(t, suite.Client, suite.TimeoutConfig, routeNN,
				[]v1.RouteParentStatus{acceptedParent}, false)
		})

		// Every UDP listener should report 1 attached route, since the route
		// implicitly attaches to all of them.
		t.Run("Every UDP listener on the Gateway has the UDPRoute attached", func(t *testing.T) {
			ready := []metav1.Condition{
				{
					Type:   string(v1.ListenerConditionAccepted),
					Status: metav1.ConditionTrue,
					Reason: "", // any reason
				},
				{
					Type:   string(v1.ListenerConditionResolvedRefs),
					Status: metav1.ConditionTrue,
					Reason: "", // any reason
				},
			}
			udpRouteKind := []v1.RouteGroupKind{{
				Group: (*v1.Group)(&v1.GroupVersion.Group),
				Kind:  v1.Kind("UDPRoute"),
			}}
			expectedListeners := []v1.ListenerStatus{
				{
					Name:           v1.SectionName("udp-1"),
					SupportedKinds: udpRouteKind,
					AttachedRoutes: 1,
					Conditions:     ready,
				},
				{
					Name:           v1.SectionName("udp-2"),
					SupportedKinds: udpRouteKind,
					AttachedRoutes: 1,
					Conditions:     ready,
				},
				{
					Name:           v1.SectionName("udp-3"),
					SupportedKinds: udpRouteKind,
					AttachedRoutes: 1,
					Conditions:     ready,
				},
			}
			kubernetes.GatewayStatusMustHaveListeners(t, suite.Client, suite.TimeoutConfig, gwNN, expectedListeners)
		})

		// Traffic to each of the three UDP listeners should reach the backend.
		for _, listener := range []string{"udp-1", "udp-2", "udp-3"} {
			t.Run("UDP echo via listener "+listener+" reaches the backend", func(t *testing.T) {
				gwAddr, err := kubernetes.WaitForGatewayAddress(t, suite.Client, suite.TimeoutConfig,
					kubernetes.NewGatewayRef(gwNN, listener))
				if err != nil {
					t.Fatalf("error getting gateway address for listener %q: %v", listener, err)
				}
				udp.ExpectEchoResponseFromBackend(t, suite.TimeoutConfig.DefaultTestTimeout, gwAddr, udp.ExpectedResponse{
					Service:   backend,
					Namespace: ns,
				})
			})
		}
	},
}
