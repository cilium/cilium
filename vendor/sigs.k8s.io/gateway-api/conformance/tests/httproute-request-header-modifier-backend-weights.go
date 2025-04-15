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
	"strings"
	"testing"

	"k8s.io/apimachinery/pkg/types"

	"sigs.k8s.io/gateway-api/conformance/utils/http"
	"sigs.k8s.io/gateway-api/conformance/utils/kubernetes"
	"sigs.k8s.io/gateway-api/conformance/utils/suite"
	"sigs.k8s.io/gateway-api/pkg/features"
)

func init() {
	ConformanceTests = append(ConformanceTests,
		HTTPRouteRequestHeaderModifierBackendWeights,
	)
}

var HTTPRouteRequestHeaderModifierBackendWeights = suite.ConformanceTest{
	ShortName:   "HTTPRouteRequestHeaderModifierBackendWeights",
	Description: "An HTTPRoute with backend request header modifier filter sends traffic to the correct backends",
	Features: []features.FeatureName{
		features.SupportGateway,
		features.SupportHTTPRouteBackendRequestHeaderModification,
		features.SupportHTTPRoute,
	},
	Manifests: []string{"tests/httproute-request-header-modifier-backend-weights.yaml"},
	Test: func(t *testing.T, suite *suite.ConformanceTestSuite) {
		ns := "gateway-conformance-infra"

		routeNN := types.NamespacedName{Name: "request-header-modifier-backend-weights", Namespace: ns}
		gwNN := types.NamespacedName{Name: "same-namespace", Namespace: ns}
		gwAddr := kubernetes.GatewayAndHTTPRoutesMustBeAccepted(t, suite.Client, suite.TimeoutConfig, suite.ControllerName, kubernetes.NewGatewayRef(gwNN), routeNN)
		kubernetes.HTTPRouteMustHaveResolvedRefsConditionsTrue(t, suite.Client, suite.TimeoutConfig, routeNN, gwNN)

		roundTripper := suite.RoundTripper

		expected := http.ExpectedResponse{
			Request:   http.Request{Path: "/"},
			Response:  http.Response{StatusCode: 200},
			Namespace: "gateway-conformance-infra",
		}

		req := http.MakeRequest(t, &expected, gwAddr, "HTTP", "http")

		// Assert request succeeds before checking traffic
		http.MakeRequestAndExpectEventuallyConsistentResponse(t, suite.RoundTripper, suite.TimeoutConfig, gwAddr, expected)

		for range 100 {
			cReq, _, err := roundTripper.CaptureRoundTrip(req)
			if err != nil {
				t.Fatalf("failed to roundtrip request: %v", err)
			}

			expectedBackends := cReq.Headers["Backend"]

			if len(expectedBackends) != 1 {
				t.Fatalf("expected a single 'Backend' header to have been set, got %d", len(expectedBackends))
			}

			if !strings.HasPrefix(cReq.Pod, expectedBackends[0]) {
				t.Fatalf(
					"expected the backendRef to have set the correct headers and sent the request to the correct pod, got %q, want %q",
					cReq.Pod,
					expectedBackends[0],
				)
			}
		}
	},
}
