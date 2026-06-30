/*
Copyright 2025 The Kubernetes Authors.

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

	"k8s.io/apimachinery/pkg/types"

	"sigs.k8s.io/gateway-api/conformance/utils/kubernetes"
	confsuite "sigs.k8s.io/gateway-api/conformance/utils/suite"
	"sigs.k8s.io/gateway-api/conformance/utils/tcp"
	"sigs.k8s.io/gateway-api/pkg/features"
)

func init() {
	ConformanceTests = append(ConformanceTests, TLSRouteTerminateSimpleSameNamespace)
}

var TLSRouteTerminateSimpleSameNamespace = confsuite.ConformanceTest{
	ShortName:   "TLSRouteTerminateSimpleSameNamespace",
	Description: "A single TLSRoute in the gateway-conformance-infra namespace attaches to a Gateway using Terminate mode in the same namespace",
	Features: []features.FeatureName{
		features.SupportGateway,
		features.SupportTLSRoute,
		features.SupportTLSRouteModeTerminate,
	},
	Provisional: true,
	Manifests:   []string{"tests/tlsroute-terminate-simple-same-namespace.yaml"},
	Test: func(t *testing.T, suite *confsuite.ConformanceTestSuite) {
		ns := confsuite.InfrastructureNamespace
		routeNN := types.NamespacedName{Name: "tlsroute-terminated-test", Namespace: ns}
		gwNN := types.NamespacedName{Name: "gateway-tlsroute-terminate", Namespace: ns}
		caCertNN := types.NamespacedName{Name: "tls-checks-ca-certificate", Namespace: ns}

		kubernetes.NamespacesMustBeReady(t, suite.Client, suite.TimeoutConfig, []string{ns})

		gwAddr, hostnames := kubernetes.GatewayAndTLSRoutesMustBeAccepted(t, suite.Client, suite.TimeoutConfig, suite.ControllerName, kubernetes.NewGatewayRef(gwNN), routeNN)
		if len(hostnames) != 1 {
			t.Fatalf("unexpected error in test configuration, found %d hostnames", len(hostnames))
		}
		serverStr := string(hostnames[0])

		caConfigMap, err := kubernetes.GetConfigMapData(suite.Client, suite.TimeoutConfig, caCertNN)
		if err != nil {
			t.Fatalf("unexpected error finding TLS secret: %v", err)
		}
		caString, ok := caConfigMap["ca.crt"]
		if !ok {
			t.Fatalf("ca.crt not found in configmap: %s/%s", caCertNN.Namespace, caCertNN.Name)
		}

		t.Run("Simple TLS request matching terminated TLSRoute should reach tcp-backend with plain text", func(t *testing.T) {
			tcp.MakeTCPRequestAndExpectEventuallyValidResponse(t, suite.TimeoutConfig, gwAddr, []byte(caString), serverStr, true,
				tcp.ExpectedResponse{
					BackendIsTLS: false, // It is terminated on the gateway
					Backend:      "tcp-backend",
					Namespace:    confsuite.InfrastructureNamespace,
					Hostname:     "", // Terminated tests do not contain a SNI attribute on the backend
				})
		})
	},
}
