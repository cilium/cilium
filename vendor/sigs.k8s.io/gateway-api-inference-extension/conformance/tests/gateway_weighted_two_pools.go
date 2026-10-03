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
	"fmt"
	"math"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/sets"
	gwhttp "sigs.k8s.io/gateway-api/conformance/utils/http"
	"sigs.k8s.io/gateway-api/conformance/utils/suite"
	gatewayfeatures "sigs.k8s.io/gateway-api/pkg/features"

	"sigs.k8s.io/gateway-api-inference-extension/conformance/resources"
	"sigs.k8s.io/gateway-api-inference-extension/conformance/utils/features"
	"sigs.k8s.io/gateway-api-inference-extension/conformance/utils/headers"
	k8sutils "sigs.k8s.io/gateway-api-inference-extension/conformance/utils/kubernetes"
)

func init() {
	ConformanceTests = append(ConformanceTests, GatewayWeightedAcrossTwoInferencePools)
}

// GatewayWeightedAcrossTwoInferencePools verifies that Gateway splits traffic across two
// InferencePools according to backendRef weights, and that each request is routed to an
// endpoint of the selected InferencePool.
var GatewayWeightedAcrossTwoInferencePools = suite.ConformanceTest{
	ShortName:   "GatewayWeightedAcrossTwoInferencePools",
	Description: "Gateway should split traffic across two InferencePools based on backendRef weights and route only to endpoints of the selected InferencePool",
	Manifests:   []string{"tests/gateway_weighted_two_pools.yaml"},
	Features: []gatewayfeatures.FeatureName{
		features.SupportInferencePool,
		gatewayfeatures.SupportGateway,
	},
	Test: func(t *testing.T, s *suite.ConformanceTestSuite) {
		const (
			hostname = "primary.example.com"
			path     = "/weighted-two-pools-test"

			// Sample size so the weight signal dominates random noise.
			totalRequests      = 200
			concurrentRequests = 5

			// These route weights must match the test manifest.
			primaryWeight   = 70
			secondaryWeight = 30
		)

		// Objects under test.
		httpRouteNN := types.NamespacedName{Name: "httproute-weighted-two-pools", Namespace: resources.AppBackendNamespace}
		gatewayNN := resources.PrimaryGatewayNN
		primaryPoolNN := resources.PrimaryInferencePoolNN
		secondaryPoolNN := types.NamespacedName{Name: "secondary-inference-pool", Namespace: resources.AppBackendNamespace}

		// Labels for the two deployments defined in base.yaml.
		primaryLabels := map[string]string{"app": "primary-inference-model-server"}
		secondaryLabels := map[string]string{"app": "secondary-inference-model-server"}

		t.Log("Verifying HTTPRoute and both InferencePools are accepted and the Gateway has an address.")
		k8sutils.HTTPRouteMustBeAcceptedAndResolved(t, s.Client, s.TimeoutConfig, httpRouteNN, gatewayNN)
		k8sutils.InferencePoolMustBeAcceptedByParent(t, s.Client, primaryPoolNN, gatewayNN)
		k8sutils.InferencePoolMustBeAcceptedByParent(t, s.Client, secondaryPoolNN, gatewayNN)
		gwAddr := k8sutils.GetGatewayEndpoint(t, s.Client, s.TimeoutConfig, gatewayNN)

		// Discover pods for each pool and build quick lookup sets.
		t.Logf("Fetching primary backend pods with labels: %v", primaryLabels)
		primaryPods, err := k8sutils.GetPodsWithLabel(t, s.Client, resources.AppBackendNamespace, primaryLabels, s.TimeoutConfig)
		require.NoError(t, err)
		require.Len(t, primaryPods, 3) // base.yaml uses 3 replicas

		t.Logf("Fetching secondary backend pods with labels: %v", secondaryLabels)
		secondaryPods, err := k8sutils.GetPodsWithLabel(t, s.Client, resources.AppBackendNamespace, secondaryLabels, s.TimeoutConfig)
		require.NoError(t, err)
		require.Len(t, secondaryPods, 3) // base.yaml uses 3 replicas

		primaryPodNames := make([]string, 0, len(primaryPods))
		primaryPodIPs := make([]string, 0, len(primaryPods))
		for _, p := range primaryPods {
			require.NotEmpty(t, p.Status.PodIP, "primary pod %s has no IP yet", p.Name)
			primaryPodNames = append(primaryPodNames, p.Name)
			primaryPodIPs = append(primaryPodIPs, p.Status.PodIP)
		}

		secondaryPodNames := make([]string, 0, len(secondaryPods))
		secondaryPodIPs := make([]string, 0, len(secondaryPods))
		for _, p := range secondaryPods {
			require.NotEmpty(t, p.Status.PodIP, "secondary pod %s has no IP yet", p.Name)
			secondaryPodNames = append(secondaryPodNames, p.Name)
			secondaryPodIPs = append(secondaryPodIPs, p.Status.PodIP)
		}

		// Provide a union list of eligible endpoints for the test. Each pool's EPP
		// should filter to endpoints that actually belong to its pool.
		allIPs := append(append([]string{}, primaryPodIPs...), secondaryPodIPs...)
		eppHeaderValue := strings.Join(allIPs, ",")

		// Warm up every pod individually across both pools to guarantee that GFE
		// backend health checks and NEGs for both pools are 100% healthy before kicking off concurrent traffic.
		allPods := append(append([]corev1.Pod{}, primaryPods...), secondaryPods...)
		for _, pod := range allPods {
			pod := pod
			t.Logf("Warming up pod %s (%s)", pod.Name, pod.Status.PodIP)
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
						Body:   `{"model":"conformance-fake-model","prompt":"Warmup"}`,
						Headers: map[string]string{
							headers.HeaderTestEppEndPointSelectionKey: pod.Status.PodIP + ":3000",
						},
					},
					Response: gwhttp.Response{
						StatusCodes: []int{http.StatusOK},
					},
					Backend:   pod.Name,
					Namespace: resources.AppBackendNamespace,
				},
			)
		}

		requestBody := `{
			"model": "conformance-fake-model",
			"prompt": "Write as if you were a critic: San Francisco"
		}`

		// Build quick lookup sets for attributing each hit to a pool by backend pod name.
		primarySet := sets.New(primaryPodNames...)
		secondarySet := sets.New(secondaryPodNames...)
		headersMap := map[string]string{
			headers.HeaderTestEppEndPointSelectionKey: eppHeaderValue,
		}
		expected := gwhttp.ExpectedResponse{
			Request: gwhttp.Request{
				Host:    hostname,
				Path:    path,
				Method:  http.MethodPost,
				Headers: headersMap,
				Body:    requestBody,
			},
			Response: gwhttp.Response{
				StatusCode: http.StatusOK,
			},
			Namespace: resources.AppBackendNamespace,
		}
		gwhttp.MakeRequestAndExpectEventuallyConsistentResponse(t, s.RoundTripper, s.TimeoutConfig, gwAddr, expected)

		var primaryHits, secondaryHits atomic.Int64
		var g errgroup.Group
		g.SetLimit(concurrentRequests)

		for range totalRequests {
			g.Go(func() error {
				timeout := time.After(2 * time.Minute)
				for {
					req := gwhttp.MakeRequest(t, &expected, gwAddr, "HTTP", "http")
					cReq, cRes, err := s.RoundTripper.CaptureRoundTrip(req)
					if err == nil {
						compErr := gwhttp.CompareRoundTrip(t, &req, cReq, cRes, expected)
						if compErr == nil {
							if primarySet.Has(cReq.Pod) {
								primaryHits.Add(1)
								return nil
							} else if secondarySet.Has(cReq.Pod) {
								secondaryHits.Add(1)
								return nil
							}
							return fmt.Errorf("request was handled by unexpected pod %q (not in either pool)", cReq.Pod)
						}
						if cRes != nil && (cRes.StatusCode == http.StatusNotFound || cRes.StatusCode == http.StatusServiceUnavailable) {
							// Transient unconverged GFE instance; back off and retry
						} else {
							return fmt.Errorf("response expectation failed: %w", compErr)
						}
					}

					select {
					case <-timeout:
						if err != nil {
							return fmt.Errorf("failed to roundtrip request after retries: %w", err)
						}
						return fmt.Errorf("response expectation failed after retries")
					case <-time.After(500 * time.Millisecond):
					}
				}
			})
		}
		require.NoError(t, g.Wait(), "requests failed")

		ph := float64(primaryHits.Load())
		sh := float64(secondaryHits.Load())
		total := ph + sh
		require.Equal(t, int64(totalRequests), int64(total), "sum of hits must equal number of attempts")
		require.Greater(t, total, 0.0)

		observedPrimary := ph / total
		expectedPrimary := float64(primaryWeight) / float64(primaryWeight+secondaryWeight)

		// A 4.5-sigma interval keeps random false failures below 0.001% at this sample size.
		sigma := math.Sqrt(expectedPrimary * (1.0 - expectedPrimary) / total)
		absTolerance := math.Max(0.10, 4.5*sigma)

		diff := math.Abs(observedPrimary - expectedPrimary)
		require.LessOrEqualf(t, diff, absTolerance,
			"weighted split out of bounds: observed primary=%.3f (hits=%d/%d), expected=%.3f, tolerance=±%.3f",
			observedPrimary, int64(ph), int64(total), expectedPrimary, absTolerance)
		t.Logf("Weighted split OK: primary=%.3f (hits=%d/%d), expected=%.3f, tolerance=±%.3f; secondary hits=%d",
			observedPrimary, int64(ph), int64(total), expectedPrimary, absTolerance, int64(sh))
	},
}
