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
	"sigs.k8s.io/gateway-api/conformance/utils/tcp"
	"sigs.k8s.io/gateway-api/pkg/features"
)

func init() {
	ConformanceTests = append(ConformanceTests, TLSRouteMixedTerminationSameNamespace)
}

var TLSRouteMixedTerminationSameNamespace = suite.ConformanceTest{
	ShortName:   "TLSRouteMixedTerminationSameNamespace",
	Description: "A Gateway with 2 TLS Listeners on different modes, on the same port must route the traffic correctly",
	Features: []features.FeatureName{
		features.SupportGateway,
		features.SupportTLSRoute,
		features.SupportTLSRouteModeTerminate,
		features.SupportTLSRouteModeMixed,
	},
	Provisional: true,
	Manifests:   []string{"tests/tlsroute-mixed-termination-same-namespace.yaml"},
	Test: func(t *testing.T, suite *suite.ConformanceTestSuite) {
		ns := "gateway-conformance-infra"
		routeTerminateNN := types.NamespacedName{Name: "gateway-conformance-mixed-terminateroute", Namespace: ns}
		routePassthroughNN := types.NamespacedName{Name: "gateway-conformance-mixed-passthroughroute", Namespace: ns}
		gwNN := types.NamespacedName{Name: "gateway-tlsroute-mixed-termination", Namespace: ns}
		caCertNN := types.NamespacedName{Name: "tls-checks-ca-certificate", Namespace: ns}
		certNN := types.NamespacedName{Name: "tls-passthrough-checks-certificate", Namespace: ns}

		kubernetes.NamespacesMustBeReady(t, suite.Client, suite.TimeoutConfig, []string{ns})

		gwAddr, hostnamesPassthrough := kubernetes.GatewayAndTLSRoutesMustBeAccepted(t, suite.Client, suite.TimeoutConfig, suite.ControllerName,
			kubernetes.NewGatewayRef(gwNN), routePassthroughNN)

		listeners := []v1.ListenerStatus{
			{
				Name: v1.SectionName("tls-terminate"),
				SupportedKinds: []v1.RouteGroupKind{{
					Group: (*v1.Group)(&v1.GroupVersion.Group),
					Kind:  v1.Kind("TLSRoute"),
				}},
				Conditions: []metav1.Condition{{
					Type:   string(v1.ListenerConditionAccepted),
					Status: metav1.ConditionTrue,
					Reason: string(v1.ListenerReasonAccepted),
				}},
				AttachedRoutes: 1,
			},
			{
				Name: v1.SectionName("tls-passthrough"),
				SupportedKinds: []v1.RouteGroupKind{{
					Group: (*v1.Group)(&v1.GroupVersion.Group),
					Kind:  v1.Kind("TLSRoute"),
				}},
				Conditions: []metav1.Condition{{
					Type:   string(v1.ListenerConditionAccepted),
					Status: metav1.ConditionTrue,
					Reason: string(v1.ListenerReasonAccepted),
				}},
				AttachedRoutes: 1,
			},
		}
		kubernetes.GatewayStatusMustHaveListeners(t, suite.Client, suite.TimeoutConfig, gwNN, listeners)

		if len(hostnamesPassthrough) != 1 {
			t.Fatalf("unexpected error in test configuration, found %d passthrough hostnames", len(hostnamesPassthrough))
		}
		serverStrPassthrough := string(hostnamesPassthrough[0])

		_, hostnamesTerminate := kubernetes.GatewayAndTLSRoutesMustBeAccepted(t, suite.Client, suite.TimeoutConfig, suite.ControllerName,
			kubernetes.NewGatewayRef(gwNN), routeTerminateNN)

		if len(hostnamesTerminate) != 1 {
			t.Fatalf("unexpected error in test configuration, found %d terminate hostnames", len(hostnamesTerminate))
		}
		serverStrTerminate := string(hostnamesTerminate[0])

		caConfigMap, err := kubernetes.GetConfigMapData(suite.Client, suite.TimeoutConfig, caCertNN)
		if err != nil {
			t.Fatalf("unexpected error finding TLS secret: %v", err)
		}
		caString, ok := caConfigMap["ca.crt"]
		if !ok {
			t.Fatalf("ca.crt not found in configmap: %s/%s", caCertNN.Namespace, caCertNN.Name)
		}

		serverCertPem, _, err := GetTLSSecret(suite.Client, certNN)
		if err != nil {
			t.Fatalf("unexpected error finding TLS secret: %v", err)
		}

		t.Run("Simple TLS request matching terminated TLSRoute should reach tcp-backend unencrypted", func(t *testing.T) {
			t.Parallel()

			tcp.MakeTCPRequestAndExpectEventuallyValidResponse(t, suite.TimeoutConfig, gwAddr, []byte(caString), serverStrTerminate, true,
				tcp.ExpectedResponse{
					BackendIsTLS: false, // It is terminated on the gateway
					Backend:      "tcp-backend",
					Namespace:    "gateway-conformance-infra",
					Hostname:     "", // Terminated tests do not contain a SNI attribute on the backend
				})
		})

		t.Run("Simple TLS request matching TLSRoute Passthrough should reach infra-backend", func(t *testing.T) {
			t.Parallel()
			tcp.MakeTCPRequestAndExpectEventuallyValidResponse(t, suite.TimeoutConfig, gwAddr, serverCertPem, serverStrPassthrough, true,
				tcp.ExpectedResponse{
					BackendIsTLS: true, // Passthrough expects a TLS Backend
					Backend:      "tcp-backend",
					Namespace:    "gateway-conformance-infra",
					Hostname:     serverStrPassthrough,
				})
		})
	},
}
