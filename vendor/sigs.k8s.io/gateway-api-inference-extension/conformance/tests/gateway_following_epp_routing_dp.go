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
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	gwhttp "sigs.k8s.io/gateway-api/conformance/utils/http"
	"sigs.k8s.io/gateway-api/conformance/utils/suite"
	gatewayfeatures "sigs.k8s.io/gateway-api/pkg/features"

	"sigs.k8s.io/gateway-api-inference-extension/conformance/resources"
	"sigs.k8s.io/gateway-api-inference-extension/conformance/utils/features"
	"sigs.k8s.io/gateway-api-inference-extension/conformance/utils/headers"
	k8sutils "sigs.k8s.io/gateway-api-inference-extension/conformance/utils/kubernetes"
)

// dpPorts are the data parallel ports exposed by the backend deployment. Update if the ports
// change in conformance/resources/base.yaml.
var dpPorts = portSet{"3000": {}, "3002": {}, "3004": {}}

func init() {
	ConformanceTests = append(ConformanceTests, GatewayFollowingEPPRoutingWithDataParallelism)
}

// GatewayFollowingEPPRoutingWithDataParallelism verifies that with multiple targetPorts (ranks)
// the gateway still routes only to pods returned by EPP.
var GatewayFollowingEPPRoutingWithDataParallelism = suite.ConformanceTest{
	ShortName:   "GatewayFollowingEPPRoutingWithDataParallelism",
	Description: "Inference gateway should restrict traffic to EPP-selected pods while EPP balances across multiple targetPorts (DP ranks)",
	Manifests:   []string{"tests/gateway_following_epp_routing_dp.yaml"},
	Features: []gatewayfeatures.FeatureName{
		features.SupportInferencePool,
		gatewayfeatures.SupportGateway,
	},
	Test: func(t *testing.T, s *suite.ConformanceTestSuite) {
		const (
			hostname            = "primary.example.com"
			path                = "/primary-gateway-dp-test"
			appPodBackendPrefix = "dp-inference-model-server" // Must match the app label in the backend pods
		)

		httpRouteNN := types.NamespacedName{Name: "httproute-for-primary-gw-dp", Namespace: resources.AppBackendNamespace}
		gatewayNN := resources.PrimaryGatewayNN
		poolNN := types.NamespacedName{Name: "dp-inference-pool", Namespace: resources.AppBackendNamespace}
		backendPodLabels := map[string]string{"app": "dp-inference-model-server"}

		t.Log("Verifying HTTPRoute and InferencePool are accepted and the Gateway has an address.")
		k8sutils.HTTPRouteMustBeAcceptedAndResolved(t, s.Client, s.TimeoutConfig, httpRouteNN, gatewayNN)
		k8sutils.InferencePoolMustBeAcceptedByParent(t, s.Client, poolNN, gatewayNN)
		gwAddr := k8sutils.GetGatewayEndpoint(t, s.Client, s.TimeoutConfig, gatewayNN)

		t.Logf("Fetching backend pods with labels: %v", backendPodLabels)
		pods, err := k8sutils.GetPodsWithLabel(t, s.Client, resources.AppBackendNamespace, backendPodLabels, s.TimeoutConfig)
		require.NoError(t, err, "Failed to get backend pods")
		require.Len(t, pods, 3, "Expected to find 3 backend pods, found %d", len(pods))

		backends := toEndpoints(pods)
		require.Len(t, backends, 3)

		podNameToIP := make(map[string]string, len(backends))
		for _, be := range backends {
			podNameToIP[be.Name] = be.IP
		}

		requestBody := `{
			"model": "conformance-fake-model",
			"prompt": "Write as if you were a critic: San Francisco"
		}`

		// Single-pod pin to ensure header filter works before main test cases.
		for _, backend := range backends {
			gwhttp.MakeRequestAndExpectEventuallyConsistentResponse(
				t,
				s.RoundTripper,
				s.TimeoutConfig,
				gwAddr,
				gwhttp.ExpectedResponse{
					Request: gwhttp.Request{
						Host:   hostname,
						Path:   path,
						Method: http.MethodPost,
						Body:   requestBody,
						Headers: map[string]string{
							headers.HeaderTestEppEndPointSelectionKey: backend.IP,
						},
					},
					Response:  gwhttp.Response{StatusCodes: []int{http.StatusOK}},
					Backend:   backend.Name,
					Namespace: resources.AppBackendNamespace,
				},
			)
		}

		testCases := []struct {
			name                                  string
			ipToAllowedPorts                      map[string]portSet
			expectAllRequestsRoutedWithinPodNames []string
		}{
			{
				name: "DP routes only to one designated pod (any rank)",
				ipToAllowedPorts: map[string]portSet{
					backends[1].IP: {}, // any of the DP ports for this IP
				},
				expectAllRequestsRoutedWithinPodNames: []string{backends[1].Name},
			},
			{
				name: "DP routes only to two designated pods; one has a fixed rank",
				ipToAllowedPorts: map[string]portSet{
					backends[0].IP: {},           // any port
					backends[2].IP: {"3002": {}}, // must be port 3002 for this IP
				},
				expectAllRequestsRoutedWithinPodNames: []string{backends[0].Name, backends[2].Name},
			},
			{
				name: "DP routes to all pods; one pod restricted to 3000,3004",
				ipToAllowedPorts: map[string]portSet{
					backends[0].IP: {},
					backends[1].IP: {"3000": {}, "3004": {}},
					backends[2].IP: {},
				},
				expectAllRequestsRoutedWithinPodNames: []string{backends[0].Name, backends[1].Name, backends[2].Name},
			},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				// Build the EPP header from the endpoint map (stable order).
				eppHeaderValue := buildEPPHeader(tc.ipToAllowedPorts)

				headersMap := map[string]string{
					headers.HeaderTestEppEndPointSelectionKey: eppHeaderValue,
				}

				assertTrafficOnlyReachesToExpectedPodsDP(
					t, s, gwAddr,
					gwhttp.ExpectedResponse{
						Request: gwhttp.Request{
							Host:    hostname,
							Path:    path,
							Method:  http.MethodPost,
							Body:    requestBody,
							Headers: headersMap,
						},
						Response:  gwhttp.Response{StatusCode: http.StatusOK},
						Backend:   appPodBackendPrefix,
						Namespace: resources.AppBackendNamespace,
					},
					tc.expectAllRequestsRoutedWithinPodNames,
					podNameToIP,
					tc.ipToAllowedPorts,
				)
			})
		}
	},
}

func assertTrafficOnlyReachesToExpectedPodsDP(
	t *testing.T,
	suite *suite.ConformanceTestSuite,
	gwAddr string,
	expected gwhttp.ExpectedResponse,
	expectedPodNames []string,
	podNameToIP map[string]string,
	ipToAllowedPorts map[string]portSet,
) {
	t.Helper()
	const (
		concurrency   = 10
		totalRequests = 100
	)

	var (
		rt = suite.RoundTripper
		g  errgroup.Group
	)
	gwhttp.MakeRequestAndExpectEventuallyConsistentResponse(t, rt, suite.TimeoutConfig, gwAddr, expected)
	g.SetLimit(concurrency)

	for i := 0; i < totalRequests; i++ {
		g.Go(func() error {
			timeout := time.After(2 * time.Minute)
			for {
				req := gwhttp.MakeRequest(t, &expected, gwAddr, "HTTP", "http")
				cReq, cRes, err := rt.CaptureRoundTrip(req)
				if err == nil {
					compErr := gwhttp.CompareRoundTrip(t, &req, cReq, cRes, expected)
					if compErr == nil {
						// Enforce no leakage to non-selected pods.
						if !slices.Contains(expectedPodNames, cReq.Pod) {
							return fmt.Errorf("unexpected pod %q (expected one of %v)", cReq.Pod, expectedPodNames)
						}

						// Validate httpPort from JSON response body vs EPP intent.
						if cReq.HTTPPort == "" {
							return errors.New("missing httpPort in echo JSON body response")
						}
						ip := podNameToIP[cReq.Pod]
						allowed, ok := ipToAllowedPorts[ip]
						if !ok {
							return fmt.Errorf("pod %q (IP %s) not present in EPP selection", cReq.Pod, ip)
						}
						if len(allowed) > 0 {
							if _, ok := allowed[cReq.HTTPPort]; !ok {
								return fmt.Errorf("unexpected httpPort %q for IP %s (allowed: %v)", cReq.HTTPPort, ip, keys(allowed))
							}
						} else {
							if _, ok := dpPorts[cReq.HTTPPort]; !ok {
								return fmt.Errorf("unexpected httpPort %q for IP %s (expected one of ports %v)", cReq.HTTPPort, ip, keys(dpPorts))
							}
						}

						return nil
					}
					if cRes != nil && (cRes.StatusCode == http.StatusNotFound || cRes.StatusCode == http.StatusServiceUnavailable) {
						// Transient unconverged GFE instance; back off and retry
					} else {
						return fmt.Errorf("expectation failed: %w", compErr)
					}
				}

				select {
				case <-timeout:
					if err != nil {
						return fmt.Errorf("failed roundtrip after retries: %w", err)
					}
					return fmt.Errorf("expectation failed after retries")
				case <-time.After(500 * time.Millisecond):
				}
			}
		})
	}
	if err := g.Wait(); err != nil {
		t.Fatalf("Requests were not confined to expected pods or failed port checks: %v", err)
	}
	t.Logf("Traffic restricted to %v and httpPort validated against EPP selection", expectedPodNames)
}

type portSet map[string]struct{}

type PodEndpoint struct {
	Name  string
	IP    string
	Ports []string
}

func keys(m portSet) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// buildEPPHeader builds the test EPP header from ip->ports. AN empty portSet => emit just "IP".
// A non-empty => emit "IP:port" for each port. Sorted for determinism.
func buildEPPHeader(ipToPorts map[string]portSet) string {
	ips := make([]string, 0, len(ipToPorts))
	for ip := range ipToPorts {
		ips = append(ips, ip)
	}
	slices.Sort(ips)

	var tokens []string
	for _, ip := range ips {
		ports := ipToPorts[ip]
		if len(ports) == 0 {
			tokens = append(tokens, ip)
			continue
		}
		ps := keys(ports)
		slices.Sort(ps)
		for _, p := range ps {
			tokens = append(tokens, fmt.Sprintf("%s:%s", ip, p))
		}
	}
	return strings.Join(tokens, ",")
}

// toEndpoints extracts name, IP, and unique containerPort values per pod.
func toEndpoints(pods []corev1.Pod) []PodEndpoint {
	out := make([]PodEndpoint, 0, len(pods))
	for _, p := range pods {
		seen := map[int32]struct{}{}
		var ports []string
		for _, c := range p.Spec.Containers {
			for _, cp := range c.Ports {
				if _, ok := seen[cp.ContainerPort]; ok {
					continue
				}
				seen[cp.ContainerPort] = struct{}{}
				ports = append(ports, strconv.Itoa(int(cp.ContainerPort)))
			}
		}
		out = append(out, PodEndpoint{
			Name:  p.Name,
			IP:    p.Status.PodIP,
			Ports: ports,
		})
	}
	return out
}
