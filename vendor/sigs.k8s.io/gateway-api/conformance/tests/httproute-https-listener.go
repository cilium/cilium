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
	"testing"

	"k8s.io/apimachinery/pkg/types"

	"sigs.k8s.io/gateway-api/conformance/utils/http"
	"sigs.k8s.io/gateway-api/conformance/utils/kubernetes"
	"sigs.k8s.io/gateway-api/conformance/utils/suite"
	"sigs.k8s.io/gateway-api/conformance/utils/tls"
	"sigs.k8s.io/gateway-api/pkg/features"
)

func init() {
	ConformanceTests = append(ConformanceTests, HTTPRouteHTTPSListener)
}

var HTTPRouteHTTPSListener = suite.ConformanceTest{
	ShortName:   "HTTPRouteHTTPSListener",
	Description: "HTTPRoute attaches to a Gateway's HTTPS listener in the same namespace",
	Features: []features.FeatureName{
		features.SupportGateway,
		features.SupportHTTPRoute,
	},
	Manifests: []string{"tests/httproute-https-listener.yaml"},
	Test: func(t *testing.T, suite *suite.ConformanceTestSuite) {
		ns := "gateway-conformance-infra"
		routeNN := types.NamespacedName{Name: "httproute-https-test", Namespace: ns}
		routeNoHostNN := types.NamespacedName{Name: "httproute-https-test-no-hostname", Namespace: ns}

		gwNN := types.NamespacedName{Name: "same-namespace-with-https-listener", Namespace: ns}
		gwAddr := kubernetes.GatewayAndHTTPRoutesMustBeAccepted(t, suite.Client, suite.TimeoutConfig, suite.ControllerName, kubernetes.NewGatewayRef(gwNN), routeNN, routeNoHostNN)
		kubernetes.HTTPRouteMustHaveResolvedRefsConditionsTrue(t, suite.Client, suite.TimeoutConfig, routeNN, gwNN)
		kubernetes.HTTPRouteMustHaveResolvedRefsConditionsTrue(t, suite.Client, suite.TimeoutConfig, routeNoHostNN, gwNN)

		certNN := types.NamespacedName{Name: "tls-validity-checks-certificate", Namespace: ns}
		cPem, keyPem, err := GetTLSSecret(suite.Client, certNN)
		if err != nil {
			t.Fatalf("unexpected error finding TLS secret: %v", err)
		}

		cases := []struct {
			host       string
			statusCode int
			backend    string
		}{
			{host: "example.org", statusCode: 200, backend: "infra-backend-v1"},
			{host: "unknown-example.org", statusCode: 404},
			{host: "second-example.org", statusCode: 200, backend: "infra-backend-v2"},
		}

		for i, tc := range cases {
			expected := http.ExpectedResponse{
				Request:   http.Request{Host: tc.host, Path: "/"},
				Response:  http.Response{StatusCode: tc.statusCode},
				Backend:   tc.backend,
				Namespace: "gateway-conformance-infra",
			}
			t.Run(expected.GetTestCaseName(i), func(t *testing.T) {
				tls.MakeTLSRequestAndExpectEventuallyConsistentResponse(t, suite.RoundTripper, suite.TimeoutConfig, gwAddr, cPem, keyPem, tc.host, expected)
			})
		}
	},
}
