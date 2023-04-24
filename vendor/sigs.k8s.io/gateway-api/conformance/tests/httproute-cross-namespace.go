/*
Copyright 2022 The Kubernetes Authors.

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
)

func init() {
	ConformanceTests = append(ConformanceTests, HTTPRouteCrossNamespace)
}

var HTTPRouteCrossNamespace = suite.ConformanceTest{
	ShortName:   "HTTPRouteCrossNamespace",
	Description: "A single HTTPRoute in the gateway-conformance-web-backend namespace should attach to Gateway in another namespace",
	Manifests:   []string{"tests/httproute-cross-namespace.yaml"},
	Test: func(t *testing.T, suite *suite.ConformanceTestSuite) {
		routeNN := types.NamespacedName{Name: "cross-namespace", Namespace: "gateway-conformance-web-backend"}
		gwNN := types.NamespacedName{Name: "backend-namespaces", Namespace: "gateway-conformance-infra"}
		gwAddr := kubernetes.GatewayAndHTTPRoutesMustBeAccepted(t, suite.Client, suite.TimeoutConfig, suite.ControllerName, kubernetes.NewGatewayRef(gwNN), routeNN)

		t.Run("Simple HTTP request should reach web-backend", func(t *testing.T) {
			http.MakeRequestAndExpectEventuallyConsistentResponse(t, suite.RoundTripper, suite.TimeoutConfig, gwAddr, http.ExpectedResponse{
				Request:   http.Request{Path: "/"},
				Response:  http.Response{StatusCode: 200},
				Backend:   "web-backend",
				Namespace: "gateway-conformance-web-backend",
			})
		})
	},
}
