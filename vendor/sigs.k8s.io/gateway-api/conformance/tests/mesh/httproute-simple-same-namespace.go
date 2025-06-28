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
	MeshConformanceTests = append(MeshConformanceTests, MeshHTTPRouteSimpleSameNamespace)
}

var MeshHTTPRouteSimpleSameNamespace = suite.ConformanceTest{
	ShortName:   "MeshHTTPRouteSimpleSameNamespace",
	Description: "A single HTTPRoute in the gateway-conformance-mesh namespace attaches to a Service in the same namespace",
	Features: []features.FeatureName{
		features.SupportMesh,
		features.SupportHTTPRoute,
	},
	Manifests: []string{"tests/mesh/httproute-simple-same-namespace.yaml"},
	Test: func(t *testing.T, s *suite.ConformanceTestSuite) {
		ns := "gateway-conformance-mesh"
		client := echo.ConnectToApp(t, s, echo.MeshAppEchoV1)
		t.Run("Simple HTTP request should reach infra-backend", func(t *testing.T) {
			client.MakeRequestAndExpectEventuallyConsistentResponse(t, http.ExpectedResponse{
				Request:   http.Request{Path: "/", Host: "echo"},
				Response:  http.Response{StatusCode: 200},
				Backend:   "echo-v1",
				Namespace: ns,
			}, s.TimeoutConfig)
		})
	},
}
