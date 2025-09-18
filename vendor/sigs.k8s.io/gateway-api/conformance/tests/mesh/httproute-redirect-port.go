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
	"testing"

	"sigs.k8s.io/gateway-api/conformance/utils/echo"
	"sigs.k8s.io/gateway-api/conformance/utils/http"
	"sigs.k8s.io/gateway-api/conformance/utils/roundtripper"
	"sigs.k8s.io/gateway-api/conformance/utils/suite"
	"sigs.k8s.io/gateway-api/pkg/features"
)

func init() {
	MeshConformanceTests = append(MeshConformanceTests, MeshHTTPRouteRedirectPort)
}

var MeshHTTPRouteRedirectPort = suite.ConformanceTest{
	ShortName:   "MeshHTTPRouteRedirectPort",
	Description: "An HTTPRoute with a port redirect filter",
	Manifests:   []string{"tests/mesh/httproute-redirect-port.yaml"},
	Features: []features.FeatureName{
		features.SupportMesh,
		features.SupportHTTPRoute,
		features.SupportMeshHTTPRouteRedirectPort,
	},
	Test: func(t *testing.T, s *suite.ConformanceTestSuite) {
		ns := "gateway-conformance-mesh"
		client := echo.ConnectToApp(t, s, echo.MeshAppEchoV1)

		testCases := []http.ExpectedResponse{
			{
				Request: http.Request{
					Host:             "echo",
					Path:             "/port",
					UnfollowRedirect: true,
				},
				Response: http.Response{
					StatusCode: 302,
				},
				RedirectRequest: &roundtripper.RedirectRequest{
					Port: "8083",
				},
				Namespace: ns,
			}, {
				Request: http.Request{
					Host:             "echo",
					Path:             "/port-and-host",
					UnfollowRedirect: true,
				},
				Response: http.Response{
					StatusCode: 302,
				},
				RedirectRequest: &roundtripper.RedirectRequest{
					Host: "example.org",
					Port: "8083",
				},
				Namespace: ns,
			}, {
				Request: http.Request{
					Host:             "echo",
					Path:             "/port-and-status",
					UnfollowRedirect: true,
				},
				Response: http.Response{
					StatusCode: 301,
				},
				RedirectRequest: &roundtripper.RedirectRequest{
					Port: "8083",
				},
				Namespace: ns,
			}, {
				Request: http.Request{
					Host:             "echo",
					Path:             "/port-and-host-and-status",
					UnfollowRedirect: true,
				},
				Response: http.Response{
					StatusCode: 302,
				},
				RedirectRequest: &roundtripper.RedirectRequest{
					Port: "8083",
					Host: "example.org",
				},
				Namespace: ns,
			},
		}
		for i := range testCases {
			// Declare tc here to avoid loop variable
			// reuse issues across parallel tests.
			tc := testCases[i]
			t.Run(tc.GetTestCaseName(i), func(t *testing.T) {
				t.Parallel()
				client.MakeRequestAndExpectEventuallyConsistentResponse(t, tc, s.TimeoutConfig)
			})
		}
	},
}
