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

	"sigs.k8s.io/gateway-api/conformance/utils/http"
	"sigs.k8s.io/gateway-api/conformance/utils/kubernetes"
	"sigs.k8s.io/gateway-api/conformance/utils/roundtripper"
	"sigs.k8s.io/gateway-api/conformance/utils/suite"
	"sigs.k8s.io/gateway-api/conformance/utils/tls"
	"sigs.k8s.io/gateway-api/pkg/features"
)

func init() {
	ConformanceTests = append(ConformanceTests, HTTPRouteHTTPSListenerDetectMisdirectedRequests)
}

var HTTPRouteHTTPSListenerDetectMisdirectedRequests = suite.ConformanceTest{
	ShortName:   "HTTPRouteHTTPSListenerDetectMisdirectedRequests",
	Description: "HTTPS listeners on the same port detect misdirected requests and return HTTP 421 when appropriate",
	Features: []features.FeatureName{
		features.SupportGateway,
		features.SupportGatewayHTTPSListenerDetectMisdirectedRequests,
		features.SupportHTTPRoute,
	},
	Manifests: []string{"tests/httproute-https-listener-detect-misdirected-requests.yaml"},
	Test: func(t *testing.T, suite *suite.ConformanceTestSuite) {
		ns := "gateway-conformance-infra"

		routeNNs := []types.NamespacedName{
			{Name: "https-listener-detect-misdirected-requests-test-1", Namespace: ns},
			{Name: "https-listener-detect-misdirected-requests-test-2", Namespace: ns},
			{Name: "https-listener-detect-misdirected-requests-test-3", Namespace: ns},
			{Name: "https-listener-detect-misdirected-requests-test-4", Namespace: ns},
		}
		gwNN := types.NamespacedName{Name: "same-namespace-with-https-listener", Namespace: ns}
		gwAddr := kubernetes.GatewayAndHTTPRoutesMustBeAccepted(t, suite.Client, suite.TimeoutConfig, suite.ControllerName, kubernetes.NewGatewayRef(gwNN), routeNNs...)
		for _, routeNN := range routeNNs {
			kubernetes.HTTPRouteMustHaveResolvedRefsConditionsTrue(t, suite.Client, suite.TimeoutConfig, routeNN, gwNN)
		}

		certNN := types.NamespacedName{Name: "tls-validity-checks-certificate", Namespace: ns}
		serverCertPem, _, err := GetTLSSecret(suite.Client, certNN)
		if err != nil {
			t.Fatalf("unexpected error finding TLS secret: %v", err)
		}

		cases := []struct {
			host       string
			statusCode int
			backend    string
			serverName string
		}{
			{serverName: "example.org", host: "example.org", statusCode: 200, backend: "infra-backend-v1"},
			{serverName: "example.org", host: "second-example.org", statusCode: 421},
			{serverName: "example.org", host: "unknown-example.org", statusCode: 404},

			{serverName: "second-example.org", host: "second-example.org", statusCode: 200, backend: "infra-backend-v2"},
			{serverName: "second-example.org", host: "example.org", statusCode: 421},
			{serverName: "second-example.org", host: "unknown-example.org", statusCode: 421},

			{serverName: "third-example.wildcard.org", host: "third-example.wildcard.org", statusCode: 200, backend: "infra-backend-v3"},
			{serverName: "third-example.wildcard.org", host: "fith-example.wildcard.org", statusCode: 200, backend: "infra-backend-v3"},
			{serverName: "third-example.wildcard.org", host: "fourth-example.wildcard.org", statusCode: 421},
			{serverName: "third-example.wildcard.org", host: "second-example.org", statusCode: 421},
			{serverName: "third-example.wildcard.org", host: "unknown-example.org", statusCode: 421},

			// Note: Since infra-backend-v4 does not exist, infra-backend-v1 is reused for the fourth HTTPRoute
			{serverName: "fourth-example.wildcard.org", host: "fourth-example.wildcard.org", statusCode: 200, backend: "infra-backend-v1"},
			{serverName: "fourth-example.wildcard.org", host: "fith-example.wildcard.org", statusCode: 421},

			{serverName: "unknown-example.org", host: "example.org", statusCode: 200, backend: "infra-backend-v1"},
			{serverName: "unknown-example.org", host: "unknown-example.org", statusCode: 404},
		}

		for i, tc := range cases {
			expected := http.ExpectedResponse{
				Request: http.Request{
					Host:     tc.host,
					Path:     "/detect-misdirected-requests",
					Protocol: roundtripper.H2Protocol,
				},
				Response:  http.Response{StatusCodes: []int{tc.statusCode}},
				Backend:   tc.backend,
				Namespace: "gateway-conformance-infra",
			}
			t.Run(expected.GetTestCaseName(i), func(t *testing.T) {
				tls.MakeTLSRequestAndExpectEventuallyConsistentResponse(t, suite.RoundTripper, suite.TimeoutConfig, gwAddr, serverCertPem, nil, nil, tc.serverName, expected)
			})
		}
	},
}
