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
	ConformanceTests = append(ConformanceTests, UDPRouteParentRefPortAndSectionName)
}

var UDPRouteParentRefPortAndSectionName = confsuite.ConformanceTest{
	ShortName:   "UDPRouteParentRefPortAndSectionName",
	Description: "A UDPRoute attaches to a UDP listener selected by port, by sectionName, or by both, and traffic to each listener is routed to the backend Service configured by the corresponding UDPRoute.",
	Manifests:   []string{"tests/udproute-parentref-port-and-section-name.yaml"},
	Features: []features.FeatureName{
		features.SupportGateway,
		features.SupportUDPRoute,
	},
	Provisional: true,
	Test: func(t *testing.T, suite *confsuite.ConformanceTestSuite) {
		ns := confsuite.InfrastructureNamespace
		gwNN := types.NamespacedName{Name: "udp-multi-listener-gateway", Namespace: ns}

		// The test creates an additional Gateway in the gateway-conformance-infra
		// namespace so we have to wait for it to be ready.
		kubernetes.NamespacesMustBeReady(t, suite.Client, suite.TimeoutConfig, []string{ns})

		group := v1.Group(v1.GroupVersion.Group)
		kind := v1.Kind("Gateway")
		gwName := v1.ObjectName(gwNN.Name)
		gwNS := v1.Namespace(ns)
		acceptedParent := func() v1.RouteParentStatus {
			return v1.RouteParentStatus{
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
		}

		// Each scenario wires a distinct listener to a dedicated backend
		// Service. Hitting a listener should route to that listener's backend
		// only, which we verify by checking the service identifier returned by
		// the UDP echo server.
		scenarios := []struct {
			name     string
			route    string
			listener string
			backend  string
		}{
			{
				name:     "UDPRoute attaches to a UDP listener by port",
				route:    "udp-route-by-port",
				listener: "by-port",
				backend:  "udp-echo-by-port",
			},
			{
				name:     "UDPRoute attaches to a UDP listener by sectionName",
				route:    "udp-route-by-section",
				listener: "by-section",
				backend:  "udp-echo-by-section",
			},
			{
				name:     "UDPRoute attaches to a UDP listener by sectionName and port",
				route:    "udp-route-by-section-and-port",
				listener: "by-section-and-port",
				backend:  "udp-echo-by-section-and-port",
			},
		}

		for _, s := range scenarios {
			t.Run(s.name, func(t *testing.T) {
				routeNN := types.NamespacedName{Name: s.route, Namespace: ns}
				kubernetes.UDPRouteMustHaveParents(t, suite.Client, suite.TimeoutConfig, routeNN,
					[]v1.RouteParentStatus{acceptedParent()}, false)

				gwAddr, err := kubernetes.WaitForGatewayAddress(t, suite.Client, suite.TimeoutConfig,
					kubernetes.NewGatewayRef(gwNN, s.listener))
				if err != nil {
					t.Fatalf("error getting gateway address for listener %q: %v", s.listener, err)
				}
				udp.ExpectEchoResponseFromBackend(t, suite.TimeoutConfig.DefaultTestTimeout, gwAddr, udp.ExpectedResponse{
					Service:   s.backend,
					Namespace: ns,
				})
			})
		}
	},
}
