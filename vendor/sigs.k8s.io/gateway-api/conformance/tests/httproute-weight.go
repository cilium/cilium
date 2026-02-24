/*
Copyright 2024 The Kubernetes Authors.

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
	"cmp"
	"errors"
	"fmt"
	"math"
	"slices"
	"strings"
	"sync"
	"testing"

	"golang.org/x/sync/errgroup"
	"k8s.io/apimachinery/pkg/types"

	"sigs.k8s.io/gateway-api/conformance/utils/http"
	"sigs.k8s.io/gateway-api/conformance/utils/kubernetes"
	"sigs.k8s.io/gateway-api/conformance/utils/suite"
	"sigs.k8s.io/gateway-api/pkg/features"
)

func init() {
	ConformanceTests = append(ConformanceTests, HTTPRouteWeight)
}

var HTTPRouteWeight = suite.ConformanceTest{
	ShortName:   "HTTPRouteWeight",
	Description: "An HTTPRoute with weighted backends",
	Manifests:   []string{"tests/httproute-weight.yaml"},
	Features: []features.FeatureName{
		features.SupportGateway,
		features.SupportHTTPRoute,
	},
	Test: func(t *testing.T, suite *suite.ConformanceTestSuite) {
		var (
			ns      = "gateway-conformance-infra"
			routeNN = types.NamespacedName{Name: "weighted-backends", Namespace: ns}
			gwNN    = types.NamespacedName{Name: "same-namespace", Namespace: ns}
			gwAddr  = kubernetes.GatewayAndHTTPRoutesMustBeAccepted(t, suite.Client, suite.TimeoutConfig, suite.ControllerName, kubernetes.NewGatewayRef(gwNN), routeNN)
		)

		kubernetes.HTTPRouteMustHaveResolvedRefsConditionsTrue(t, suite.Client, suite.TimeoutConfig, routeNN, gwNN)

		t.Run("Requests should have a distribution that matches the weight", func(t *testing.T) {
			expected := http.ExpectedResponse{
				Request:   http.Request{Path: "/"},
				Response:  http.Response{StatusCode: 200},
				Namespace: "gateway-conformance-infra",
			}

			// Assert request succeeds before doing our distribution check
			http.MakeRequestAndExpectEventuallyConsistentResponse(t, suite.RoundTripper, suite.TimeoutConfig, gwAddr, expected)

			for i := 0; i < 10; i++ {
				if err := testDistribution(t, suite, gwAddr, expected); err != nil {
					t.Logf("Traffic distribution test failed (%d/10): %s", i+1, err)
				} else {
					return
				}
			}
			t.Fatal("Weighted distribution tests failed")
		})
	},
}

func testDistribution(t *testing.T, suite *suite.ConformanceTestSuite, gwAddr string, expected http.ExpectedResponse) error {
	const (
		concurrentRequests  = 10
		tolerancePercentage = 0.05
		totalRequests       = 500.0
	)
	var (
		roundTripper = suite.RoundTripper

		g               errgroup.Group
		seenMutex       sync.Mutex
		seen            = make(map[string]float64, 3 /* number of backends */)
		req             = http.MakeRequest(t, &expected, gwAddr, "HTTP", "http")
		expectedWeights = map[string]float64{
			"infra-backend-v1": 0.7,
			"infra-backend-v2": 0.3,
			"infra-backend-v3": 0.0,
		}
	)
	g.SetLimit(concurrentRequests)
	for i := 0.0; i < totalRequests; i++ {
		g.Go(func() error {
			cReq, cRes, err := roundTripper.CaptureRoundTrip(req)
			if err != nil {
				return fmt.Errorf("failed to roundtrip request: %w", err)
			}
			if err := http.CompareRequest(t, &req, cReq, cRes, expected); err != nil {
				return fmt.Errorf("response expectation failed for request: %w", err)
			}

			seenMutex.Lock()
			defer seenMutex.Unlock()

			for expectedBackend := range expectedWeights {
				if strings.HasPrefix(cReq.Pod, expectedBackend) {
					seen[expectedBackend]++
					return nil
				}
			}

			return fmt.Errorf("request was handled by an unexpected pod %q", cReq.Pod)
		})
	}

	if err := g.Wait(); err != nil {
		return fmt.Errorf("error while sending requests: %w", err)
	}

	var errs []error
	if len(seen) != 2 {
		errs = append(errs, fmt.Errorf("expected only two backends to receive traffic"))
	}

	for wantBackend, wantPercent := range expectedWeights {
		gotCount, ok := seen[wantBackend]

		if !ok && wantPercent != 0.0 {
			errs = append(errs, fmt.Errorf("expect traffic to hit backend %q - but none was received", wantBackend))
			continue
		}

		gotPercent := gotCount / totalRequests

		if math.Abs(gotPercent-wantPercent) > tolerancePercentage {
			errs = append(errs, fmt.Errorf("backend %q weighted traffic of %v not within tolerance %v (+/-%f)",
				wantBackend,
				gotPercent,
				wantPercent,
				tolerancePercentage,
			))
		}
	}
	slices.SortFunc(errs, func(a, b error) int {
		return cmp.Compare(a.Error(), b.Error())
	})
	return errors.Join(errs...)
}
