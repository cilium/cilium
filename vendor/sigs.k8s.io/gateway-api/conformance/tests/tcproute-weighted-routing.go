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

	"k8s.io/apimachinery/pkg/types"

	"sigs.k8s.io/gateway-api/conformance/utils/kubernetes"
	confsuite "sigs.k8s.io/gateway-api/conformance/utils/suite"
	"sigs.k8s.io/gateway-api/conformance/utils/tcp"
	"sigs.k8s.io/gateway-api/conformance/utils/tlog"
	"sigs.k8s.io/gateway-api/conformance/utils/weight"
	"sigs.k8s.io/gateway-api/pkg/features"
)

func init() {
	ConformanceTests = append(ConformanceTests, TCPRouteWeightedRouting)
}

var TCPRouteWeightedRouting = confsuite.ConformanceTest{
	ShortName:   "TCPRouteWeightedRouting",
	Description: "A TCPRoute with multiple weighted backends should distribute TCP traffic across the backends in proportion to the configured weights, and a backend with weight 0 should receive no traffic.",
	Manifests:   []string{"tests/tcproute-weighted-routing.yaml"},
	Features: []features.FeatureName{
		features.SupportGateway,
		features.SupportTCPRoute,
	},
	Provisional: true,
	Test: func(t *testing.T, suite *confsuite.ConformanceTestSuite) {
		ns := confsuite.InfrastructureNamespace
		gwNN := types.NamespacedName{Name: "tcp-weighted-gateway", Namespace: ns}
		routeNN := types.NamespacedName{Name: "tcp-weighted-route", Namespace: ns}

		// The test creates an additional Gateway in the gateway-conformance-infra
		// namespace so we have to wait for it to be ready.
		kubernetes.NamespacesMustBeReady(t, suite.Client, suite.TimeoutConfig, []string{ns})

		gwAddr := kubernetes.GatewayAndTCPRoutesMustBeAccepted(t, suite.Client, suite.TimeoutConfig, suite.ControllerName,
			kubernetes.NewGatewayRef(gwNN, "tcp"), routeNN)

		t.Run("TCP traffic should be distributed across the weighted backends and skip the zero-weighted backend", func(t *testing.T) {
			expectedWeights := map[string]float64{
				"tcp-backend-v1": 0.7,
				"tcp-backend-v2": 0.3,
				"tcp-backend-v3": 0.0,
			}

			tcp.ExpectAddressBeAvailable(t, suite.TimeoutConfig.DefaultPollInterval, suite.TimeoutConfig.MaxTimeToConsistency, gwAddr)

			sender := weight.NewFunctionBasedSender(func() (string, error) {
				return tcp.EchoSendOnce(t.Context(), gwAddr, suite.TimeoutConfig.RequestTimeout)
			})

			for i := range weight.MaxTestRetries {
				if err := weight.TestWeightedDistribution(sender, expectedWeights); err != nil {
					tlog.Logf(t, "TCP weighted distribution attempt %d/%d failed: %s", i+1, weight.MaxTestRetries, err)
				} else {
					return
				}
			}
			t.Fatal("TCP weighted distribution did not converge within tolerance")
		})
	},
}
