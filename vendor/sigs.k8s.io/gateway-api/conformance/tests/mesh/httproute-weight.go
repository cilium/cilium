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

package meshtests

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

	"sigs.k8s.io/gateway-api/conformance/utils/echo"
	"sigs.k8s.io/gateway-api/conformance/utils/http"
	"sigs.k8s.io/gateway-api/conformance/utils/suite"
	"sigs.k8s.io/gateway-api/pkg/features"
)

func init() {
	MeshConformanceTests = append(MeshConformanceTests, MeshHTTPRouteWeight)
}

var MeshHTTPRouteWeight = suite.ConformanceTest{
	ShortName:   "MeshHTTPRouteWeight",
	Description: "An HTTPRoute with weighted backends",
	Manifests:   []string{"tests/mesh/httproute-weight.yaml"},
	Features: []features.FeatureName{
		features.SupportMesh,
		features.SupportHTTPRoute,
	},
	Test: func(t *testing.T, s *suite.ConformanceTestSuite) {
		client := echo.ConnectToApp(t, s, echo.MeshAppEchoV1)

		t.Run("Requests should have a distribution that matches the weight", func(t *testing.T) {
			host := "echo"
			expected := http.ExpectedResponse{
				Request:   http.Request{Path: "/", Host: host},
				Response:  http.Response{StatusCode: 200},
				Namespace: "gateway-conformance-mesh",
			}

			// Assert request succeeds before doing our distribution check
			client.MakeRequestAndExpectEventuallyConsistentResponse(t, expected, s.TimeoutConfig)
			for i := 0; i < 10; i++ {
				if err := testDistribution(t, client, expected); err != nil {
					t.Logf("Traffic distribution test failed (%d/10): %s", i+1, err)
				} else {
					return
				}
			}
			t.Fatal("Weighted distribution tests failed")
		})
	},
}

func testDistribution(t *testing.T, client echo.MeshPod, expected http.ExpectedResponse) error {
	const (
		concurrentRequests  = 10
		tolerancePercentage = 0.05
		totalRequests       = 500.0
	)
	var (
		g               errgroup.Group
		seenMutex       sync.Mutex
		seen            = make(map[string]float64, 2 /* number of backends */)
		expectedWeights = map[string]float64{
			"echo-v1": 0.7,
			"echo-v2": 0.3,
		}
	)
	g.SetLimit(concurrentRequests)
	for i := 0.0; i < totalRequests; i++ {
		g.Go(func() error {
			uniqueExpected := expected
			if err := http.AddEntropy(&uniqueExpected); err != nil {
				return fmt.Errorf("error adding entropy: %w", err)
			}
			_, cRes, err := client.CaptureRequestResponseAndCompare(t, uniqueExpected)
			if err != nil {
				return fmt.Errorf("failed: %w", err)
			}

			seenMutex.Lock()
			defer seenMutex.Unlock()

			for expectedBackend := range expectedWeights {
				if strings.HasPrefix(cRes.Hostname, expectedBackend) {
					seen[expectedBackend]++
					return nil
				}
			}

			return fmt.Errorf("request was handled by an unexpected pod %q", cRes.Hostname)
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
