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
	"sigs.k8s.io/gateway-api/conformance/utils/tcp"
	"sigs.k8s.io/gateway-api/pkg/features"
)

func init() {
	ConformanceTests = append(ConformanceTests, TCPRouteParentRefPortAndSectionName)
}

var TCPRouteParentRefPortAndSectionName = confsuite.ConformanceTest{
	ShortName:   "TCPRouteParentRefPortAndSectionName",
	Description: "A TCPRoute attaches to a TCP listener by port, by sectionName, or by both.",
	Manifests:   []string{"tests/tcproute-parentref-port-and-section-name.yaml"},
	Features: []features.FeatureName{
		features.SupportGateway,
		features.SupportTCPRoute,
	},
	Provisional: true,
	Test: func(t *testing.T, suite *confsuite.ConformanceTestSuite) {
		ns := confsuite.InfrastructureNamespace
		gwNN := types.NamespacedName{Name: "tcp-multi-listener-gateway", Namespace: ns}

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

		expectBackendForListener := func(t *testing.T, listener, backend string) {
			t.Helper()
			gwAddr, err := kubernetes.WaitForGatewayAddress(t, suite.Client, suite.TimeoutConfig,
				kubernetes.NewGatewayRef(gwNN, listener))
			if err != nil {
				t.Fatalf("error getting gateway address for listener %q: %v", listener, err)
			}
			tcp.MakeTCPRequestAndExpectEventuallyValidResponse(t, suite.TimeoutConfig, gwAddr, nil, "", false,
				tcp.ExpectedResponse{
					Backend:   backend,
					Namespace: ns,
				})
		}

		t.Run("TCPRoute attaches to a TCP listener by port", func(t *testing.T) {
			routeNN := types.NamespacedName{Name: "tcp-route-by-port", Namespace: ns}
			kubernetes.TCPRouteMustHaveParents(t, suite.Client, suite.TimeoutConfig, routeNN,
				[]v1.RouteParentStatus{acceptedParent()}, false)
			expectBackendForListener(t, "one", "tcp-echo-one")
		})

		t.Run("TCPRoute attaches to a TCP listener by sectionName", func(t *testing.T) {
			routeNN := types.NamespacedName{Name: "tcp-route-by-section", Namespace: ns}
			kubernetes.TCPRouteMustHaveParents(t, suite.Client, suite.TimeoutConfig, routeNN,
				[]v1.RouteParentStatus{acceptedParent()}, false)
			expectBackendForListener(t, "two", "tcp-echo-two")
		})

		t.Run("TCPRoute attaches to a TCP listener by sectionName and port", func(t *testing.T) {
			routeNN := types.NamespacedName{Name: "tcp-route-by-section-and-port", Namespace: ns}
			kubernetes.TCPRouteMustHaveParents(t, suite.Client, suite.TimeoutConfig, routeNN,
				[]v1.RouteParentStatus{acceptedParent()}, false)
			expectBackendForListener(t, "three", "tcp-echo-three")
		})
	},
}
