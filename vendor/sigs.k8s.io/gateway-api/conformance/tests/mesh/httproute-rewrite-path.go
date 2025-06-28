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
	"sigs.k8s.io/gateway-api/conformance/utils/suite"
	"sigs.k8s.io/gateway-api/pkg/features"
)

func init() {
	MeshConformanceTests = append(MeshConformanceTests, MeshHTTPRouteRewritePath)
}

var MeshHTTPRouteRewritePath = suite.ConformanceTest{
	ShortName:   "MeshHTTPRouteRewritePath",
	Description: "An HTTPRoute with path rewrite filter",
	Features: []features.FeatureName{
		features.SupportMesh,
		features.SupportHTTPRoute,
		features.SupportMeshHTTPRouteRewritePath,
	},
	Manifests: []string{"tests/mesh/httproute-rewrite-path.yaml"},
	Test: func(t *testing.T, s *suite.ConformanceTestSuite) {
		ns := "gateway-conformance-mesh"
		client := echo.ConnectToApp(t, s, echo.MeshAppEchoV1)
		cases := []http.ExpectedResponse{
			{
				Request: http.Request{
					Path: "/prefix/one/two",
					Host: "echo",
				},
				ExpectedRequest: &http.ExpectedRequest{
					Request: http.Request{
						Path: "/one/two",
					},
				},
				Backend:   "echo-v1",
				Namespace: ns,
			},
			{
				Request: http.Request{
					Path: "/strip-prefix/three",
					Host: "echo",
				},
				ExpectedRequest: &http.ExpectedRequest{
					Request: http.Request{
						Path: "/three",
					},
				},
				Backend:   "echo-v1",
				Namespace: ns,
			},
			{
				Request: http.Request{
					Path: "/strip-prefix",
					Host: "echo",
				},
				ExpectedRequest: &http.ExpectedRequest{
					Request: http.Request{
						Path: "/",
					},
				},
				Backend:   "echo-v1",
				Namespace: ns,
			},
			{
				Request: http.Request{
					Path: "/full/one/two",
					Host: "echo",
				},
				ExpectedRequest: &http.ExpectedRequest{
					Request: http.Request{
						Path: "/one",
					},
				},
				Backend:   "echo-v1",
				Namespace: ns,
			},
			{
				Request: http.Request{
					Host: "echo",
					Path: "/full/rewrite-path-and-modify-headers/test",
					Headers: map[string]string{
						"X-Header-Remove":     "remove-val",
						"X-Header-Add-Append": "append-val-1",
						"X-Header-Set":        "set-val",
					},
				},
				ExpectedRequest: &http.ExpectedRequest{
					Request: http.Request{
						Path: "/test",
						Headers: map[string]string{
							"X-Header-Add":        "header-val-1",
							"X-Header-Add-Append": "append-val-1,header-val-2",
							"X-Header-Set":        "set-overwrites-values",
						},
					},
					AbsentHeaders: []string{"X-Header-Remove"},
				},
				Backend:   "echo-v1",
				Namespace: ns,
			},
			{
				Request: http.Request{
					Host: "echo",
					Path: "/prefix/rewrite-path-and-modify-headers/one",
					Headers: map[string]string{
						"X-Header-Remove":     "remove-val",
						"X-Header-Add-Append": "append-val-1",
						"X-Header-Set":        "set-val",
					},
				},
				ExpectedRequest: &http.ExpectedRequest{
					Request: http.Request{
						Path: "/prefix/one",
						Headers: map[string]string{
							"X-Header-Add":        "header-val-1",
							"X-Header-Add-Append": "append-val-1,header-val-2",
							"X-Header-Set":        "set-overwrites-values",
						},
					},
					AbsentHeaders: []string{"X-Header-Remove"},
				},
				Backend:   "echo-v1",
				Namespace: ns,
			},
		}
		for i := range cases {
			// Declare tc here to avoid loop variable
			// reuse issues across parallel tests.
			tc := cases[i]
			t.Run(tc.GetTestCaseName(i), func(t *testing.T) {
				client.MakeRequestAndExpectEventuallyConsistentResponse(t, tc, s.TimeoutConfig)
			})
		}
	},
}
