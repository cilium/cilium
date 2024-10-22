/*
Copyright 2023 The Kubernetes Authors.

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
	"sigs.k8s.io/gateway-api/pkg/features"
)

func init() {
	ConformanceTests = append(ConformanceTests, HTTPRouteRequestMultipleMirrors)
}

var HTTPRouteRequestMultipleMirrors = suite.ConformanceTest{
	ShortName:   "HTTPRouteRequestMultipleMirrors",
	Description: "An HTTPRoute with multiple request mirror filters",
	Manifests:   []string{"tests/httproute-request-multiple-mirrors.yaml"},
	Features: []features.FeatureName{
		features.SupportGateway,
		features.SupportHTTPRoute,
		features.SupportHTTPRouteRequestMirror,
		features.SupportHTTPRouteRequestMultipleMirrors,
	},
	Test: func(t *testing.T, suite *suite.ConformanceTestSuite) {
		ns := "gateway-conformance-infra"
		routeNN := types.NamespacedName{Name: "request-multiple-mirrors", Namespace: ns}
		gwNN := types.NamespacedName{Name: "same-namespace", Namespace: ns}
		gwAddr := kubernetes.GatewayAndHTTPRoutesMustBeAccepted(t, suite.Client, suite.TimeoutConfig, suite.ControllerName, kubernetes.NewGatewayRef(gwNN), routeNN)

		testCases := []http.ExpectedResponse{
			{
				Request: http.Request{
					Path: "/multi-mirror",
				},
				ExpectedRequest: &http.ExpectedRequest{
					Request: http.Request{
						Path: "/multi-mirror",
					},
				},
				Backend: "infra-backend-v1",
				MirroredTo: []http.BackendRef{
					{
						Name:      "infra-backend-v2",
						Namespace: ns,
					},
					{
						Name:      "infra-backend-v3",
						Namespace: ns,
					},
				},
				Namespace: ns,
			}, {
				Request: http.Request{
					Path: "/multi-mirror-and-modify-request-headers",
					Headers: map[string]string{
						"X-Header-Remove":     "remove-val",
						"X-Header-Add-Append": "append-val-1",
					},
				},
				ExpectedRequest: &http.ExpectedRequest{
					Request: http.Request{
						Path: "/multi-mirror-and-modify-request-headers",
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
				MirroredTo: []http.BackendRef{
					{
						Name:      "infra-backend-v2",
						Namespace: ns,
					},
					{
						Name:      "infra-backend-v3",
						Namespace: ns,
					},
				},
			},
		}
		for i := range testCases {
			// Declare tc here to avoid loop variable
			// reuse issues across parallel tests.
			tc := testCases[i]
			t.Run(tc.GetTestCaseName(i), func(t *testing.T) {
				t.Parallel()
				http.MakeRequestAndExpectEventuallyConsistentResponse(t, suite.RoundTripper, suite.TimeoutConfig, gwAddr, tc)
				http.ExpectMirroredRequest(t, suite.Client, suite.Clientset, tc.MirroredTo, tc.Request.Path)
			})
		}
	},
}
