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
	"fmt"
	"net/url"
	"testing"
	"time"

	"github.com/google/uuid"
	"k8s.io/apimachinery/pkg/types"

	"sigs.k8s.io/gateway-api/conformance/utils/http"
	"sigs.k8s.io/gateway-api/conformance/utils/kubernetes"
	confsuite "sigs.k8s.io/gateway-api/conformance/utils/suite"
	"sigs.k8s.io/gateway-api/conformance/utils/tlog"
	"sigs.k8s.io/gateway-api/pkg/features"
)

func init() {
	ConformanceTests = append(ConformanceTests, HTTPRouteRetry)
}

var HTTPRouteRetry = confsuite.ConformanceTest{
	ShortName:   "HTTPRouteRetry",
	Description: "An HTTPRoute that has a Retry policy configured should retry failed requests according to the specified codes and attempt limits, returning a successful response when the backend recovers within the retry budget and surfacing the original error when it does not.",
	Manifests:   []string{"tests/httproute-retry.yaml"},
	Features: []features.FeatureName{
		features.SupportGateway,
		features.SupportHTTPRoute,
		features.SupportHTTPRouteRetry,
	},
	Test: func(t *testing.T, suite *confsuite.ConformanceTestSuite) {
		ns := confsuite.InfrastructureNamespace
		routeNN := types.NamespacedName{Name: "retries", Namespace: ns}
		gwNN := types.NamespacedName{Name: "same-namespace", Namespace: ns}
		gwAddr := kubernetes.GatewayAndHTTPRoutesMustBeAccepted(t, suite.Client, suite.TimeoutConfig, suite.ControllerName, kubernetes.NewGatewayRef(gwNN), routeNN)
		kubernetes.HTTPRouteMustHaveResolvedRefsConditionsTrue(t, suite.Client, suite.TimeoutConfig, routeNN, gwNN)

		type args struct {
			path                  string
			retrySimulationConfig url.Values
		}
		testCases := []struct {
			name string
			args args
			want http.Response
		}{
			{
				name: "succeeds after 2 retries when retry is configured for status code 500 and max attempts is 3",
				args: args{
					path: "/retry/code-500-attempts-3",
					retrySimulationConfig: url.Values{
						"responseCode": []string{"500"},
						"succeedAfter": []string{"2"},
					},
				},
				want: http.Response{StatusCode: 200},
			},
			{
				name: "fails when required retries on 500 exceed max attempts",
				args: args{
					path: "/retry/code-500-attempts-3",
					retrySimulationConfig: url.Values{
						"responseCode": []string{"500"},
						"succeedAfter": []string{"4"},
					},
				},
				want: http.Response{StatusCode: 500},
			},
			{
				name: "does not retry on 503 when retry is only configured for status code 500",
				args: args{
					path: "/retry/code-500-attempts-3",
					retrySimulationConfig: url.Values{
						"responseCode": []string{"503"},
						"succeedAfter": []string{"2"},
					},
				},
				want: http.Response{StatusCode: 503},
			},

			{
				name: "succeeds after 1 retry on 500 when retry is configured for all status code and max attempts is 2",
				args: args{
					path: "/retry/code-all-attempts-2",
					retrySimulationConfig: url.Values{
						"responseCode": []string{"500"},
						"succeedAfter": []string{"1"},
					},
				},
				want: http.Response{StatusCode: 200},
			},
			{
				name: "fails when required retries on 500 exceed max attempts",
				args: args{
					path: "/retry/code-all-attempts-2",
					retrySimulationConfig: url.Values{
						"responseCode": []string{"500"},
						"succeedAfter": []string{"3"},
					},
				},
				want: http.Response{StatusCode: 500},
			},
			{
				name: "succeeds after 1 retry on 502 when retry is configured for all status code and max attempts is 2",
				args: args{
					path: "/retry/code-all-attempts-2",
					retrySimulationConfig: url.Values{
						"responseCode": []string{"502"},
						"succeedAfter": []string{"1"},
					},
				},
				want: http.Response{StatusCode: 200},
			},
			{
				name: "fails when required retries on 502 exceed max attempts",
				args: args{
					path: "/retry/code-all-attempts-2",
					retrySimulationConfig: url.Values{
						"responseCode": []string{"502"},
						"succeedAfter": []string{"3"},
					},
				},
				want: http.Response{StatusCode: 502},
			},
			{
				name: "succeeds after 1 retry on 503 when retry is configured for all status code and max attempts is 2",
				args: args{
					path: "/retry/code-all-attempts-2",
					retrySimulationConfig: url.Values{
						"responseCode": []string{"503"},
						"succeedAfter": []string{"1"},
					},
				},
				want: http.Response{StatusCode: 200},
			},
			{
				name: "fails when required retries on 503 exceed max attempts",
				args: args{
					path: "/retry/code-all-attempts-2",
					retrySimulationConfig: url.Values{
						"responseCode": []string{"503"},
						"succeedAfter": []string{"3"},
					},
				},
				want: http.Response{StatusCode: 503},
			},
			{
				name: "succeeds after 1 retry on 504 when retry is configured for all status code and max attempts is 2",
				args: args{
					path: "/retry/code-all-attempts-2",
					retrySimulationConfig: url.Values{
						"responseCode": []string{"504"},
						"succeedAfter": []string{"1"},
					},
				},
				want: http.Response{StatusCode: 200},
			},
			{
				name: "fails when required retries on 504 exceed max attempts",
				args: args{
					path: "/retry/code-all-attempts-2",
					retrySimulationConfig: url.Values{
						"responseCode": []string{"504"},
						"succeedAfter": []string{"3"},
					},
				},
				want: http.Response{StatusCode: 504},
			},
		}
		for i := range testCases {
			// Declare tc here to avoid loop variable reuse issues across parallel tests.
			tc := testCases[i]
			t.Run(fmt.Sprintf("%d request to '%s' %s", i, tc.args.path, tc.name), func(t *testing.T) {
				t.Parallel()
				assertConsistentRetryBehaviour(t, suite, gwAddr, ns, tc.args.path, tc.args.retrySimulationConfig, tc.want)
			})
		}
	},
}

func assertConsistentRetryBehaviour(t *testing.T, suite *confsuite.ConformanceTestSuite, gwAddr string, ns string, path string, values url.Values, response http.Response) {
	t.Helper()

	http.AwaitConvergence(t, suite.TimeoutConfig.RequiredConsecutiveSuccesses, suite.TimeoutConfig.MaxTimeToConsistency, func(elapsed time.Duration) bool {
		// regenerate UUID on each probe so the retry simulation handler in the echo-basic backend tracks retries independently
		values.Set("uuid", uuid.New().String())

		expectedResponse := http.ExpectedResponse{
			Request: http.Request{
				Path: path + "?" + values.Encode(),
			},
			Response:  response,
			Backend:   confsuite.InfraBackendServiceNameV3,
			Namespace: ns,
		}

		req := http.MakeRequest(t, &expectedResponse, gwAddr, "HTTP", "http")

		cReq, cRes, err := suite.RoundTripper.CaptureRoundTrip(req)
		if err != nil {
			tlog.Logf(t, "Request failed, not ready yet: %v (after %v)", err.Error(), elapsed)
			return false
		}

		if err := http.CompareRoundTrip(t, &req, cReq, cRes, expectedResponse); err != nil {
			tlog.Logf(t, "Response expectation failed for request: %+v  not ready yet: %v (after %v)", req, err, elapsed)
			return false
		}

		return true
	})
	tlog.Logf(t, "Request passed")
}
