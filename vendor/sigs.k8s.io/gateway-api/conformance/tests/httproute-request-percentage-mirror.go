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
	"regexp"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"

	"sigs.k8s.io/gateway-api/conformance/utils/config"
	"sigs.k8s.io/gateway-api/conformance/utils/http"
	"sigs.k8s.io/gateway-api/conformance/utils/kubernetes"
	"sigs.k8s.io/gateway-api/conformance/utils/roundtripper"
	"sigs.k8s.io/gateway-api/conformance/utils/suite"
	"sigs.k8s.io/gateway-api/conformance/utils/tlog"
	"sigs.k8s.io/gateway-api/pkg/features"
)

const (
	concurrentRequests    = 10
	tolerancePercentage   = 5.0
	totalRequests         = 500.0
	numDistributionChecks = 5
)

func init() {
	ConformanceTests = append(ConformanceTests, HTTPRouteRequestPercentageMirror)
}

var HTTPRouteRequestPercentageMirror = suite.ConformanceTest{
	ShortName:   "HTTPRouteRequestPercentageMirror",
	Description: "An HTTPRoute with percentage based request mirroring",
	Manifests:   []string{"tests/httproute-request-percentage-mirror.yaml"},
	Features: []features.FeatureName{
		features.SupportGateway,
		features.SupportHTTPRoute,
		features.SupportHTTPRouteRequestPercentageMirror,
	},
	Provisional: true,
	Test: func(t *testing.T, suite *suite.ConformanceTestSuite) {
		var (
			ns      = "gateway-conformance-infra"
			routeNN = types.NamespacedName{Name: "request-percentage-mirror", Namespace: ns}
			gwNN    = types.NamespacedName{Name: "same-namespace", Namespace: ns}
			gwAddr  = kubernetes.GatewayAndHTTPRoutesMustBeAccepted(t, suite.Client, suite.TimeoutConfig, suite.ControllerName, kubernetes.NewGatewayRef(gwNN), routeNN)
		)

		kubernetes.HTTPRouteMustHaveResolvedRefsConditionsTrue(t, suite.Client, suite.TimeoutConfig, routeNN, gwNN)

		testCases := []http.ExpectedResponse{
			{
				Request:   http.Request{Path: "/percent-mirror"},
				Namespace: ns,
				ExpectedRequest: &http.ExpectedRequest{
					Request: http.Request{
						Path: "/percent-mirror",
					},
				},
				Backend: "infra-backend-v1",
				MirroredTo: []http.MirroredBackend{
					{
						BackendRef: http.BackendRef{
							Name:      "infra-backend-v2",
							Namespace: ns,
						},
						Percent: ptr.To(int32(20)),
					},
				},
			}, {
				Request:   http.Request{Path: "/percent-mirror-fraction"},
				Namespace: ns,
				ExpectedRequest: &http.ExpectedRequest{
					Request: http.Request{
						Path: "/percent-mirror-fraction",
					},
				},
				Backend: "infra-backend-v1",
				MirroredTo: []http.MirroredBackend{
					{
						BackendRef: http.BackendRef{
							Name:      "infra-backend-v2",
							Namespace: ns,
						},
						Percent: ptr.To(int32(50)),
					},
				},
			}, {
				Request: http.Request{
					Path: "/percent-mirror-and-modify-headers",
					Headers: map[string]string{
						"X-Header-Remove":     "remove-val",
						"X-Header-Add-Append": "append-val-1",
					},
				},
				ExpectedRequest: &http.ExpectedRequest{
					Request: http.Request{
						Path: "/percent-mirror-and-modify-headers",
						Headers: map[string]string{
							"X-Header-Add":        "header-val-1",
							"X-Header-Add-Append": "append-val-1,header-val-2",
							"X-Header-Set":        "set-overwrites-values",
						},
					},
					AbsentHeaders: []string{"X-Header-Remove"},
				},
				Namespace: ns,
				Backend:   "infra-backend-v1",
				MirroredTo: []http.MirroredBackend{
					{
						BackendRef: http.BackendRef{
							Name:      "infra-backend-v2",
							Namespace: ns,
						},
						Percent: ptr.To(int32(35)),
					},
				},
			},
		}

		for i := range testCases {
			expected := testCases[i]
			t.Run(expected.GetTestCaseName(i), func(t *testing.T) {
				// Assert request succeeds before doing our distribution check
				http.MakeRequestAndExpectEventuallyConsistentResponse(t, suite.RoundTripper, suite.TimeoutConfig, gwAddr, expected)

				// Override to not have more requests than expected
				var dedicatedTimeoutConfig config.TimeoutConfig
				dedicatedTimeoutConfig = suite.TimeoutConfig
				dedicatedTimeoutConfig.RequiredConsecutiveSuccesses = 1
				// used to limit number of parallel go routines
				semaphore := make(chan struct{}, concurrentRequests)
				var wg sync.WaitGroup

				for k := 0; k < numDistributionChecks; k++ {
					timeNow := time.Now()
					for j := 0; j < totalRequests; j++ {
						wg.Add(1)
						semaphore <- struct{}{}
						go func(t *testing.T, r roundtripper.RoundTripper, timeoutConfig config.TimeoutConfig, gwAddr string, expected http.ExpectedResponse) {
							defer wg.Done()
							defer func() { <-semaphore }()
							http.MakeRequestAndExpectEventuallyConsistentResponse(t, r, timeoutConfig, gwAddr, expected)
						}(t, suite.RoundTripper, dedicatedTimeoutConfig, gwAddr, expected)
					}
					wg.Wait()
					if err := testMirroredRequestsDistribution(t, suite, expected, timeNow); err != nil {
						t.Logf("Traffic distribution test failed (%d/%d): %s", k+1, numDistributionChecks, err)
						time.Sleep(2 * time.Second)
					} else {
						return
					}
				}
				t.Fatal("Percentage based mirror distribution tests failed")
			})
		}
	},
}

func testMirroredRequestsDistribution(t *testing.T, suite *suite.ConformanceTestSuite, expected http.ExpectedResponse, timeVal time.Time) error {
	mirrorPods := expected.MirroredTo
	for i, mirrorPod := range mirrorPods {
		if mirrorPod.Name == "" {
			tlog.Fatalf(t, "Mirrored BackendRef[%d].Name wasn't provided in the testcase, this test should only check http request mirror.", i)
		}
	}

	var mu sync.Mutex
	mirroredCounts := make(map[string]int)

	for _, mirrorPod := range mirrorPods {
		require.Eventually(t, func() bool {
			mirrorLogRegexp := regexp.MustCompile(fmt.Sprintf("Echoing back request made to \\%s to client", expected.Request.Path))

			tlog.Log(t, "Searching for the mirrored request log")
			tlog.Logf(t, `Reading "%s/%s" logs`, mirrorPod.Namespace, mirrorPod.Name)
			logs, err := kubernetes.DumpEchoLogs(mirrorPod.Namespace, mirrorPod.Name, suite.Client, suite.Clientset, timeVal)
			if err != nil {
				tlog.Logf(t, `Couldn't read "%s/%s" logs: %v`, mirrorPod.Namespace, mirrorPod.Name, err)
				return false
			}

			count := 0
			for _, log := range logs {
				if mirrorLogRegexp.MatchString(log) {
					count++
				}
			}
			mu.Lock()
			mirroredCounts[mirrorPod.Name] += count
			mu.Unlock()

			return true
		}, 60*time.Second, time.Millisecond*100, fmt.Sprintf(`Couldn't verify the logs for "%s/%s"`, mirrorPod.Namespace, mirrorPod.Name))
	}

	var errs []error

	for _, mirrorPod := range mirrorPods {
		expected := float64(totalRequests) * float64(*mirrorPod.Percent) / 100.0
		minExpected := expected * (1 - tolerancePercentage/100)
		maxExpected := expected * (1 + tolerancePercentage/100)

		actual := float64(mirroredCounts[mirrorPod.Name])
		tlog.Logf(t, "Pod: %s, Expected: %f (min: %f, max: %f), Actual: %f", mirrorPod.Name, expected, minExpected, maxExpected, actual)

		if actual < minExpected || actual > maxExpected {
			errs = append(errs, fmt.Errorf("Pod %s did not meet the mirroring percentage within tolerance. Expected between %f and %f, but got %f", mirrorPod.Name, minExpected, maxExpected, actual))
		}
	}
	if len(errs) > 0 {
		return errors.Join(errs...)
	}
	tlog.Log(t, "Validated mirrored request logs across all desired backends within the given tolerance")
	return nil
}
