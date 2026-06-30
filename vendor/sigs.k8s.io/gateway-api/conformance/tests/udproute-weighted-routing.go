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
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/types"

	"sigs.k8s.io/gateway-api/conformance/echo-basic/udpechoserver"
	"sigs.k8s.io/gateway-api/conformance/utils/kubernetes"
	confsuite "sigs.k8s.io/gateway-api/conformance/utils/suite"
	"sigs.k8s.io/gateway-api/conformance/utils/tlog"
	"sigs.k8s.io/gateway-api/conformance/utils/weight"
	"sigs.k8s.io/gateway-api/pkg/features"
)

func init() {
	ConformanceTests = append(ConformanceTests, UDPRouteWeightedRouting)
}

var UDPRouteWeightedRouting = confsuite.ConformanceTest{
	ShortName:   "UDPRouteWeightedRouting",
	Description: "A UDPRoute with multiple weighted backends should distribute UDP traffic across the backends in proportion to the configured weights, and a backend with weight 0 should not receive any traffic.",
	Manifests:   []string{"tests/udproute-weighted-routing.yaml"},
	Features: []features.FeatureName{
		features.SupportGateway,
		features.SupportUDPRoute,
	},
	Provisional: true,
	Test: func(t *testing.T, suite *confsuite.ConformanceTestSuite) {
		ns := confsuite.InfrastructureNamespace
		gwNN := types.NamespacedName{Name: "udp-weighted-gateway", Namespace: ns}
		routeNN := types.NamespacedName{Name: "udp-weighted-route", Namespace: ns}

		// The test creates an additional Gateway in the gateway-conformance-infra
		// namespace so we have to wait for it to be ready.
		kubernetes.NamespacesMustBeReady(t, suite.Client, suite.TimeoutConfig, []string{ns})

		gwAddr := kubernetes.GatewayAndUDPRoutesMustBeAccepted(t, suite.Client, suite.TimeoutConfig, suite.ControllerName,
			kubernetes.NewGatewayRef(gwNN, "udp"), routeNN)

		t.Run("UDP traffic should be distributed across the weighted backends", func(t *testing.T) {
			// udp-backend-v3 has weight 0 and must not receive any traffic.
			// Including it in expectedWeights at 0.0 ensures any traffic
			// landing on it would be caught by weight.TestWeightedDistribution.
			expectedWeights := map[string]float64{
				"udp-backend-v1": 0.7,
				"udp-backend-v2": 0.3,
				"udp-backend-v3": 0.0,
			}

			sender := weight.NewFunctionBasedSender(func() (string, error) {
				return udpEchoSendOnce(t.Context(), gwAddr, 2*time.Second)
			})

			for i := range weight.MaxTestRetries {
				if err := weight.TestWeightedDistribution(sender, expectedWeights); err != nil {
					tlog.Logf(t, "UDP weighted distribution attempt %d/%d failed: %s", i+1, weight.MaxTestRetries, err)
				} else {
					return
				}
			}
			t.Fatal("UDP weighted distribution did not converge within tolerance")
		})
	},
}

// udpEchoSendOnce sends a single UDP datagram to gwAddr and returns the pod
// name from the JSON envelope returned by the udpechoserver.
func udpEchoSendOnce(ctx context.Context, gwAddr string, timeout time.Duration) (string, error) {
	var dialer net.Dialer
	conn, err := dialer.DialContext(ctx, "udp", gwAddr)
	if err != nil {
		return "", fmt.Errorf("dialing UDP %s: %w", gwAddr, err)
	}
	defer conn.Close()

	if err = conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return "", fmt.Errorf("setting UDP deadline: %w", err)
	}

	if _, err = conn.Write([]byte("gateway-api-conformance-udp-weight\n")); err != nil {
		return "", fmt.Errorf("writing UDP probe: %w", err)
	}

	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		return "", fmt.Errorf("reading UDP echo response: %w", err)
	}

	var resp udpechoserver.EchoResponse
	if err := json.Unmarshal(buf[:n], &resp); err != nil {
		return "", fmt.Errorf("decoding UDP echo response %q: %w", string(buf[:n]), err)
	}
	if resp.Pod == "" {
		return "", fmt.Errorf("UDP echo response missing pod name: %q", string(buf[:n]))
	}
	return resp.Pod, nil
}

// extractBackendName trims the {deployment-hash}-{pod-hash} suffix from a pod
// name to recover the Deployment name. Pod names follow the pattern
// {deployment}-{rs-hash}-{pod-hash}; if the input doesn't match the pattern
// the original name is returned.
func extractBackendName(podName string) string {
	parts := strings.Split(podName, "-")
	if len(parts) < 3 {
		return podName
	}
	return strings.Join(parts[:len(parts)-2], "-")
}
