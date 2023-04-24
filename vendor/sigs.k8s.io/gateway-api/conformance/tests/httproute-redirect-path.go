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
	"sigs.k8s.io/gateway-api/conformance/utils/roundtripper"
	"sigs.k8s.io/gateway-api/conformance/utils/suite"
)

func init() {
	ConformanceTests = append(ConformanceTests, HTTPRouteRedirectPath)
}

var HTTPRouteRedirectPath = suite.ConformanceTest{
	ShortName:   "HTTPRouteRedirectPath",
	Description: "An HTTPRoute with scheme redirect filter",
	Manifests:   []string{"tests/httproute-redirect-path.yaml"},
	Features:    []suite.SupportedFeature{suite.SupportHTTPRoutePathRedirect},
	Test: func(t *testing.T, suite *suite.ConformanceTestSuite) {
		ns := "gateway-conformance-infra"
		routeNN := types.NamespacedName{Name: "redirect-path", Namespace: ns}
		gwNN := types.NamespacedName{Name: "same-namespace", Namespace: ns}
		gwAddr := kubernetes.GatewayAndHTTPRoutesMustBeAccepted(t, suite.Client, suite.TimeoutConfig, suite.ControllerName, kubernetes.NewGatewayRef(gwNN), routeNN)

		testCases := []http.ExpectedResponse{{
			Request: http.Request{
				Path:             "/original-prefix/lemon",
				UnfollowRedirect: true,
			},
			Response: http.Response{
				StatusCode: 302,
			},
			RedirectRequest: &roundtripper.RedirectRequest{
				Path: "/replacement-prefix/lemon",
			},
			Namespace: ns,
		}, {
			Request: http.Request{
				Path:             "/full/path/original",
				UnfollowRedirect: true,
			},
			Response: http.Response{
				StatusCode: 302,
			},
			RedirectRequest: &roundtripper.RedirectRequest{
				Path: "/full-path-replacement",
			},
			Namespace: ns,
		}, {
			Request: http.Request{
				Path:             "/path-and-host",
				UnfollowRedirect: true,
			},
			Response: http.Response{
				StatusCode: 302,
			},
			RedirectRequest: &roundtripper.RedirectRequest{
				Host: "example.org",
				Path: "/replacement-prefix",
			},
			Namespace: ns,
		}, {
			Request: http.Request{
				Path:             "/path-and-status",
				UnfollowRedirect: true,
			},
			Response: http.Response{
				StatusCode: 301,
			},
			RedirectRequest: &roundtripper.RedirectRequest{
				Path: "/replacement-prefix",
			},
			Namespace: ns,
		}, {
			Request: http.Request{
				Path:             "/full-path-and-host",
				UnfollowRedirect: true,
			},
			Response: http.Response{
				StatusCode: 302,
			},
			RedirectRequest: &roundtripper.RedirectRequest{
				Host: "example.org",
				Path: "/replacement-full",
			},
			Namespace: ns,
		}, {
			Request: http.Request{
				Path:             "/full-path-and-status",
				UnfollowRedirect: true,
			},
			Response: http.Response{
				StatusCode: 301,
			},
			RedirectRequest: &roundtripper.RedirectRequest{
				Path: "/replacement-full",
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
				http.MakeRequestAndExpectEventuallyConsistentResponse(t, suite.RoundTripper, suite.TimeoutConfig, gwAddr, tc)
			})
		}
	},
}
