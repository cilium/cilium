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
	ConformanceTests = append(ConformanceTests, HTTPRouteResponseHeaderModifier)
}

var HTTPRouteResponseHeaderModifier = suite.ConformanceTest{
	ShortName:   "HTTPRouteResponseHeaderModifier",
	Description: "An HTTPRoute has response header modifier filters applied correctly",
	Features: []suite.SupportedFeature{
		suite.SupportGateway,
		suite.SupportHTTPRoute,
		suite.SupportHTTPResponseHeaderModification,
	},
	Manifests: []string{"tests/httproute-response-header-modifier.yaml"},
	Test: func(t *testing.T, suite *suite.ConformanceTestSuite) {
		ns := "gateway-conformance-infra"
		routeNN := types.NamespacedName{Name: "response-header-modifier", Namespace: ns}
		gwNN := types.NamespacedName{Name: "same-namespace", Namespace: ns}
		gwAddr := kubernetes.GatewayAndHTTPRoutesMustBeAccepted(t, suite.Client, suite.TimeoutConfig, suite.ControllerName, kubernetes.NewGatewayRef(gwNN), routeNN)
		kubernetes.HTTPRouteMustHaveResolvedRefsConditionsTrue(t, suite.Client, suite.TimeoutConfig, routeNN, gwNN)

		testCases := []http.ExpectedResponse{{
			Request: http.Request{
				Path: "/set",
			},
			BackendSetResponseHeaders: map[string]string{
				"Some-Other-Header": "val",
			},
			Response: http.Response{
				Headers: map[string]string{
					"Some-Other-Header": "val",
					"X-Header-Set":      "set-overwrites-values",
				},
			},
			Backend:   "infra-backend-v1",
			Namespace: ns,
		}, {
			Request: http.Request{
				Path: "/set",
			},
			BackendSetResponseHeaders: map[string]string{
				"Some-Other-Header": "val",
				"X-Header-Set":      "some-other-value",
			},
			Response: http.Response{
				Headers: map[string]string{
					"Some-Other-Header": "val",
					"X-Header-Set":      "set-overwrites-values",
				},
			},
			Backend:   "infra-backend-v1",
			Namespace: ns,
		}, {
			Request: http.Request{
				Path: "/add",
			},
			BackendSetResponseHeaders: map[string]string{
				"Some-Other-Header": "val",
			},
			Response: http.Response{
				Headers: map[string]string{
					"Some-Other-Header": "val",
					"X-Header-Add":      "add-appends-values",
				},
			},
			Backend:   "infra-backend-v1",
			Namespace: ns,
		}, {
			Request: http.Request{
				Path: "/add",
			},
			BackendSetResponseHeaders: map[string]string{
				"Some-Other-Header": "val",
				"X-Header-Add":      "some-other-value",
			},
			Response: http.Response{
				Headers: map[string]string{
					"Some-Other-Header": "val",
					"X-Header-Add":      "some-other-value,add-appends-values",
				},
			},
			Backend:   "infra-backend-v1",
			Namespace: ns,
		}, {
			Request: http.Request{
				Path: "/remove",
			},
			BackendSetResponseHeaders: map[string]string{
				"X-Header-Remove": "val",
			},
			Response: http.Response{
				AbsentHeaders: []string{"X-Header-Remove"},
			},
			Backend:   "infra-backend-v1",
			Namespace: ns,
		}, {
			Request: http.Request{
				Path: "/multiple",
			},
			BackendSetResponseHeaders: map[string]string{
				"X-Header-Set-2":    "set-val-2",
				"X-Header-Add-2":    "add-val-2",
				"X-Header-Remove-2": "remove-val-2",
				"Another-Header":    "another-header-val",
				"X-Header-Remove-1": "val",
			},
			Response: http.Response{
				Headers: map[string]string{
					"X-Header-Set-1": "header-set-1",
					"X-Header-Set-2": "header-set-2",
					"X-Header-Add-1": "header-add-1",
					"X-Header-Add-2": "add-val-2,header-add-2",
					"X-Header-Add-3": "header-add-3",
					"Another-Header": "another-header-val",
				},
				AbsentHeaders: []string{"X-Header-Remove-1", "X-Header-Remove-2"},
			},
			Backend:   "infra-backend-v1",
			Namespace: ns,
		}, {
			Request: http.Request{
				Path: "/case-insensitivity",
			},
			BackendSetResponseHeaders: map[string]string{
				"x-header-set":    "original-val-set",
				"x-header-add":    "original-val-add",
				"x-header-remove": "original-val-remove",
				"Another-Header":  "another-header-val",
			},
			Response: http.Response{
				Headers: map[string]string{
					"X-Header-Set":      "header-set",
					"X-Header-Add":      "original-val-add,header-add",
					"X-Lowercase-Add":   "lowercase-add",
					"X-Mixedcase-Add-1": "mixedcase-add-1",
					"X-Mixedcase-Add-2": "mixedcase-add-2",
					"X-Uppercase-Add":   "uppercase-add",
					"Another-Header":    "another-header-val",
				},
				AbsentHeaders: []string{"x-header-remove", "X-Header-Remove"},
			},
			Backend:   "infra-backend-v1",
			Namespace: ns,
		}, {
			Request: http.Request{
				Path: "/response-and-request-header-modifiers",
				Headers: map[string]string{
					"X-Header-Remove":     "remove-val",
					"X-Header-Add-Append": "append-val-1",
					"X-Header-Echo":       "echo",
				},
			},
			BackendSetResponseHeaders: map[string]string{
				"X-Header-Set-2":    "set-val-2",
				"X-Header-Add-2":    "add-val-2",
				"X-Header-Remove-2": "remove-val-2",
				"Another-Header":    "another-header-val",
				"X-Header-Remove-1": "remove-val-1",
				"X-Header-Echo":     "echo",
			},
			ExpectedRequest: &http.ExpectedRequest{
				Request: http.Request{
					Path: "/response-and-request-header-modifiers",
					Headers: map[string]string{
						"X-Header-Add":        "header-val-1",
						"X-Header-Set":        "set-overwrites-values",
						"X-Header-Add-Append": "append-val-1,header-val-2",
						"X-Header-Echo":       "echo",
					},
				},
				AbsentHeaders: []string{"X-Header-Remove"},
			},
			Response: http.Response{
				Headers: map[string]string{
					"X-Header-Set-1": "header-set-1",
					"X-Header-Set-2": "header-set-2",
					"X-Header-Add-1": "header-add-1",
					"X-Header-Add-2": "add-val-2,header-add-2",
					"Another-Header": "another-header-val",
					"X-Header-Echo":  "echo",
				},
				AbsentHeaders: []string{"X-Header-Remove-1", "X-Header-Remove-2"},
			},
			Backend:   "infra-backend-v1",
			Namespace: ns,
		}}

		for i := range testCases {
			// Declare tc here to avoid loop variable
			// reuse issues across parallel tests.
			tc := testCases[i]
			t.Run(tc.GetTestCaseName(i), func(t *testing.T) {
				t.Parallel()
				http.MakeRequestAndExpectEventuallyConsistentResponse(t, suite.RoundTripper, suite.TimeoutConfig, gwAddr, tc)
			})
		}
	},
}
