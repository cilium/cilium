/*
Copyright The Kubernetes Authors.

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
	ConformanceTests = append(ConformanceTests, HTTPRouteCORS)
}

var HTTPRouteCORS = suite.ConformanceTest{
	ShortName:   "HTTPRouteCORS",
	Description: "An HTTPRoute with CORS filter should allow CORS requests from specified origins",
	Manifests:   []string{"tests/httproute-cors.yaml"},
	Features: []features.FeatureName{
		features.SupportGateway,
		features.SupportHTTPRoute,
		features.SupportHTTPRouteCORS,
	},
	Test: func(t *testing.T, suite *suite.ConformanceTestSuite) {
		ns := "gateway-conformance-infra"
		routeNN1 := types.NamespacedName{Name: "cors-multiple-origins-methods-headers", Namespace: ns}
		routeNN2 := types.NamespacedName{Name: "cors-wildcard-methods", Namespace: ns}
		routeNN3 := types.NamespacedName{Name: "cors-wildcard-origin", Namespace: ns}
		routeNN4 := types.NamespacedName{Name: "cors-wildcard-methods-headers", Namespace: ns}
		gwNN := types.NamespacedName{Name: "same-namespace", Namespace: ns}
		gwAddr := kubernetes.GatewayAndHTTPRoutesMustBeAccepted(t, suite.Client, suite.TimeoutConfig, suite.ControllerName, kubernetes.NewGatewayRef(gwNN), routeNN1, routeNN2)
		kubernetes.HTTPRouteMustHaveResolvedRefsConditionsTrue(t, suite.Client, suite.TimeoutConfig, routeNN1, gwNN)
		kubernetes.HTTPRouteMustHaveResolvedRefsConditionsTrue(t, suite.Client, suite.TimeoutConfig, routeNN2, gwNN)
		kubernetes.HTTPRouteMustHaveResolvedRefsConditionsTrue(t, suite.Client, suite.TimeoutConfig, routeNN3, gwNN)
		kubernetes.HTTPRouteMustHaveResolvedRefsConditionsTrue(t, suite.Client, suite.TimeoutConfig, routeNN4, gwNN)

		testCases := []http.ExpectedResponse{
			{
				TestCaseName: "CORS preflight request from an exact matching origin should be allowed",
				Request: http.Request{
					Path:   "/cors-1",
					Method: "OPTIONS",
					Headers: map[string]string{
						"Origin":                         "https://www.foo.com",
						"access-control-request-method":  "GET",
						"access-control-request-headers": "x-header-1, x-header-2",
					},
				},
				// Set the expected request properties and namespace to empty strings.
				// This is a workaround to avoid the test failure.
				// The response body is empty because the request is a preflight request,
				// so we can't get the request properties from the echoserver.
				ExpectedRequest: &http.ExpectedRequest{
					Request: http.Request{
						Host:    "",
						Method:  "OPTIONS",
						Path:    "",
						Headers: nil,
					},
				},
				Namespace: "",
				Response: http.Response{
					StatusCodes: []int{200, 204},
					ValidHeaderValues: map[string][]string{
						"access-control-allow-origin": {"https://www.foo.com"},
						"access-control-allow-methods": {
							"GET, OPTIONS",
							"OPTIONS, GET",
						},
						"access-control-allow-headers": {
							"x-header-1, x-header-2",
							"x-header-2, x-header-1",
						},
						"access-control-expose-headers": {
							"x-header-3, x-header-4",
							"x-header-4, x-header-3",
						},
						"access-control-max-age":           {"3600"},
						"access-control-allow-credentials": {"true"},
					},
					// Ignore whitespace when comparing the response headers. This is because some
					// implementations add a space after each comma, and some don't. Both are valid.
					IgnoreWhitespace: true,
				},
			},
			{
				TestCaseName: "CORS preflight request from a wildcard matching origin should be allowed",
				Request: http.Request{
					Path:   "/cors-1",
					Method: "OPTIONS",
					Headers: map[string]string{
						"Origin":                         "https://www.bar.com",
						"access-control-request-method":  "GET",
						"access-control-request-headers": "x-header-1, x-header-2",
					},
				},
				// Set the expected request properties and namespace to empty strings.
				// This is a workaround to avoid the test failure.
				// The response body is empty because the request is a preflight request,
				// so we can't get the request properties from the echoserver.
				ExpectedRequest: &http.ExpectedRequest{
					Request: http.Request{
						Host:    "",
						Method:  "OPTIONS",
						Path:    "",
						Headers: nil,
					},
				},
				Namespace: "",
				Response: http.Response{
					StatusCodes: []int{200, 204},
					ValidHeaderValues: map[string][]string{
						"access-control-allow-origin": {"https://www.bar.com"},
						"access-control-allow-methods": {
							"GET, OPTIONS",
							"OPTIONS, GET",
						},
						"access-control-allow-headers": {
							"x-header-1, x-header-2",
							"x-header-2, x-header-1",
						},
						"access-control-expose-headers": {
							"x-header-3, x-header-4",
							"x-header-4, x-header-3",
						},
						"access-control-max-age":           {"3600"},
						"access-control-allow-credentials": {"true"},
					},
					// Ignore whitespace when comparing the response headers. This is because some
					// implementations add a space after each comma, and some don't. Both are valid.
					IgnoreWhitespace: true,
				},
			},
			{
				TestCaseName: "CORS preflight request from a wildcard matching any number of periods left to '*' should be allowed",
				Request: http.Request{
					Path:   "/cors-1",
					Method: "OPTIONS",
					Headers: map[string]string{
						"Origin":                         "https://xpto.www.bar.com",
						"access-control-request-method":  "GET",
						"access-control-request-headers": "x-header-1, x-header-2",
					},
				},
				// Set the expected request properties and namespace to empty strings.
				// This is a workaround to avoid the test failure.
				// The response body is empty because the request is a preflight request,
				// so we can't get the request properties from the echoserver.
				ExpectedRequest: &http.ExpectedRequest{
					Request: http.Request{
						Host:    "",
						Method:  "OPTIONS",
						Path:    "",
						Headers: nil,
					},
				},
				Namespace: "",
				Response: http.Response{
					StatusCodes: []int{200, 204},
					ValidHeaderValues: map[string][]string{
						"access-control-allow-origin": {"https://xpto.www.bar.com"},
						"access-control-allow-methods": {
							"GET, OPTIONS",
							"OPTIONS, GET",
						},
						"access-control-allow-headers": {
							"x-header-1, x-header-2",
							"x-header-2, x-header-1",
						},
						"access-control-expose-headers": {
							"x-header-3, x-header-4",
							"x-header-4, x-header-3",
						},
						"access-control-max-age":           {"3600"},
						"access-control-allow-credentials": {"true"},
					},
					// Ignore whitespace when comparing the response headers. This is because some
					// implementations add a space after each comma, and some don't. Both are valid.
					IgnoreWhitespace: true,
				},
			},
			{
				TestCaseName: "CORS preflight request from a non-matching origin should not be allowed",
				Request: http.Request{
					Path:   "/cors-1",
					Method: "OPTIONS",
					Headers: map[string]string{
						"Origin":                        "https://foobar.com",
						"access-control-request-method": "GET",
					},
				},
				// Set the expected request properties and namespace to empty strings.
				// This is a workaround to avoid the test failure.
				// The response body is empty because the request is a preflight request,
				// so we can't get the request properties from the echoserver.
				ExpectedRequest: &http.ExpectedRequest{
					Request: http.Request{
						Host:    "",
						Method:  "OPTIONS",
						Path:    "",
						Headers: nil,
					},
				},
				Namespace: "",
				Response: http.Response{
					StatusCodes: []int{200, 204, 403},
					AbsentHeaders: []string{
						"access-control-allow-origin",
					},
				},
			},
			{
				TestCaseName: "Simple request from an exact matching origin should be allowed",
				Namespace:    ns,
				Request: http.Request{
					Path:   "/cors-1",
					Method: "GET",
					Headers: map[string]string{
						"Origin":                         "https://www.foo.com",
						"access-control-request-method":  "GET",
						"access-control-request-headers": "x-header-1, x-header-2",
					},
				},
				Response: http.Response{
					StatusCode: 200,
					Headers: map[string]string{
						"access-control-allow-origin": "https://www.foo.com",
					},
				},
			},
			{
				TestCaseName: "Simple request from a wildcard matching origin should be allowed",
				Namespace:    ns,
				Request: http.Request{
					Path:   "/cors-1",
					Method: "GET",
					Headers: map[string]string{
						"Origin":                         "https://www.bar.com",
						"access-control-request-method":  "GET",
						"access-control-request-headers": "x-header-1, x-header-2",
					},
				},
				Response: http.Response{
					StatusCode: 200,
					Headers: map[string]string{
						"access-control-allow-origin": "https://www.bar.com",
					},
				},
			},
			{
				TestCaseName: "Simple request from a non-matching origin should not be allowed",
				Namespace:    ns,
				Request: http.Request{
					Path:   "/cors-1",
					Method: "GET",
					Headers: map[string]string{
						"Origin":                        "https://foobar.com",
						"access-control-request-method": "GET",
					},
				},
				Response: http.Response{
					AbsentHeaders: []string{
						"access-control-allow-origin",
					},
				},
			},
			{
				TestCaseName: "CORS preflight request with POST method should be allowed by allowMethods with wildcard",
				Request: http.Request{
					Path:   "/cors-2",
					Method: "OPTIONS",
					Headers: map[string]string{
						"Origin":                        "https://www.foo.com",
						"access-control-request-method": "POST",
					},
				},
				// Set the expected request properties and namespace to empty strings.
				// This is a workaround to avoid the test failure.
				// The response body is empty because the request is a preflight request,
				// so we can't get the request properties from the echoserver.
				ExpectedRequest: &http.ExpectedRequest{
					Request: http.Request{
						Host:    "",
						Method:  "OPTIONS",
						Path:    "",
						Headers: nil,
					},
				},
				Namespace: "",
				Response: http.Response{
					StatusCodes: []int{200, 204},
					ValidHeaderValues: map[string][]string{
						"access-control-allow-methods": {"POST", "*"},
					},
					Headers: map[string]string{
						"access-control-allow-origin": "https://www.foo.com",
					},
					AbsentHeaders: []string{"access-control-allow-credentials"},
				},
			},
			{
				TestCaseName: "CORS preflight request should not receive access-control-allow-credentials header without access-control-allow-credentials set to true",
				Request: http.Request{
					Path:   "/cors-2",
					Method: "OPTIONS",
					Headers: map[string]string{
						"Origin":                        "https://www.foo.com",
						"access-control-request-method": "POST",
					},
				},
				// Set the expected request properties and namespace to empty strings.
				// This is a workaround to avoid the test failure.
				// The response body is empty because the request is a preflight request,
				// so we can't get the request properties from the echoserver.
				ExpectedRequest: &http.ExpectedRequest{
					Request: http.Request{
						Host:    "",
						Method:  "OPTIONS",
						Path:    "",
						Headers: nil,
					},
				},
				Namespace: "",
				Response: http.Response{
					StatusCodes:   []int{200, 204},
					AbsentHeaders: []string{"Access-Control-Allow-Credentials"},
				},
			},
			{
				TestCaseName: "Pre-flight request from a wildcard origin should return header with '*' or with the requested Origin",
				Namespace:    "",
				Request: http.Request{
					Path:   "/cors-wildcard-origin",
					Method: "OPTIONS",
					Headers: map[string]string{
						"Origin":                        "https://foobar.com",
						"access-control-request-method": "PUT",
					},
				},
				ExpectedRequest: &http.ExpectedRequest{
					Request: http.Request{
						Host:    "",
						Method:  "OPTIONS",
						Path:    "",
						Headers: nil,
					},
				},
				Response: http.Response{
					StatusCodes: []int{200, 204},
					ValidHeaderValues: map[string][]string{
						// The access-control-allow-origin for a wildcard domain depends on the implementation.
						// Envoy enforces the return of the same requested Origin, while NGINX an others may return a "*"
						// per the spec in case this is a non-authenticated request
						"access-control-allow-origin": {
							"https://foobar.com",
							"*",
						},
						"access-control-allow-methods": {"PUT"},
					},
					AbsentHeaders: []string{"Access-Control-Allow-Credentials"},
				},
			},
			{
				TestCaseName: "Pre-flight request from a wildcard origin containing a port should return header with '*' or with the requested Origin",
				Namespace:    "",
				Request: http.Request{
					Path:   "/cors-wildcard-origin",
					Method: "OPTIONS",
					Headers: map[string]string{
						"Origin":                        "https://foobar.com:12345",
						"access-control-request-method": "PUT",
					},
				},
				ExpectedRequest: &http.ExpectedRequest{
					Request: http.Request{
						Host:    "",
						Method:  "OPTIONS",
						Path:    "",
						Headers: nil,
					},
				},
				Response: http.Response{
					StatusCodes: []int{200, 204},
					ValidHeaderValues: map[string][]string{
						// The access-control-allow-origin for a wildcard domain depends on the implementation.
						// Envoy enforces the return of the same requested Origin, while NGINX an others may return a "*"
						// per the spec in case this is a non-authenticated request

						"access-control-allow-origin": {
							"https://foobar.com:12345",
							"*",
						},
						"access-control-allow-methods": {"PUT"},
					},
					AbsentHeaders: []string{"Access-Control-Allow-Credentials"},
				},
			},
			{
				TestCaseName: "Request from a wildcard origin containing a port should return header with '*' or with the requested Origin",
				Namespace:    ns,
				Request: http.Request{
					Path:   "/cors-wildcard-origin",
					Method: "PUT",
					Headers: map[string]string{
						"Origin": "https://foobar.com:12345",
					},
				},
				Response: http.Response{
					StatusCode: 200,
					ValidHeaderValues: map[string][]string{
						// The access-control-allow-origin for a wildcard domain depends on the implementation.
						// Envoy enforces the return of the same requested Origin, while NGINX an others may return a "*"
						// per the spec in case this is a non-authenticated request

						"access-control-allow-origin": {
							"https://foobar.com:12345",
							"*",
						},
					},
				},
			},
			{
				TestCaseName: "Simple request from a wildcard origin should return header with '*' or with the requested Origin",
				Namespace:    ns,
				Request: http.Request{
					Path:   "/cors-wildcard-origin",
					Method: "PUT",
					Headers: map[string]string{
						"Origin": "https://foobar.com",
					},
				},
				Response: http.Response{
					StatusCode: 200,
					ValidHeaderValues: map[string][]string{
						// The access-control-allow-origin for a wildcard domain depends on the implementation.
						// Envoy enforces the return of the same requested Origin, while NGINX an others may return a "*"
						// per the spec in case this is a non-authenticated request
						"access-control-allow-origin": {
							"https://foobar.com",
							"*",
						},
					},
					AbsentHeaders: []string{"Access-Control-Allow-Credentials"},
				},
			},
			{
				TestCaseName: "CORS preflight request requesting auth and specific method and headers should be allowed and always echo the origin",
				Request: http.Request{
					Path:   "/cors-wildcard-methods-headers",
					Method: "OPTIONS",
					Headers: map[string]string{
						"Origin":                         "https://other.foo.com",
						"access-control-request-method":  "PUT",
						"access-control-request-headers": "x-header-1, x-header-2",
						// The actual request following this preflight request
						// may contain credentials here.
					},
				},
				// Set the expected request properties and namespace to empty strings.
				// This is a workaround to avoid the test failure.
				// The response body is empty because the request is a preflight request,
				// so we can't get the request properties from the echoserver.
				ExpectedRequest: &http.ExpectedRequest{
					Request: http.Request{
						Host:    "",
						Method:  "OPTIONS",
						Path:    "",
						Headers: nil,
					},
				},
				Namespace: "",
				Response: http.Response{
					StatusCodes: []int{200, 204},
					ValidHeaderValues: map[string][]string{
						"access-control-allow-origin":  {"https://other.foo.com"},
						"access-control-allow-methods": {"PUT"},
						"access-control-allow-headers": {
							"x-header-1, x-header-2",
							"x-header-2, x-header-1",
						},
						"access-control-allow-credentials": {"true"},
					},
					// Ignore whitespace when comparing the response headers. This is because some
					// implementations add a space after each comma, and some don't. Both are valid.
					IgnoreWhitespace: true,
				},
			},
			{
				TestCaseName: "CORS preflight request requesting auth and specific method and headers should hide auth headers on unauth path",
				Request: http.Request{
					Path:   "/cors-wildcard-methods-headers-unauth",
					Method: "OPTIONS",
					Headers: map[string]string{
						"Origin":                         "https://other.foo.com",
						"access-control-request-method":  "PUT",
						"access-control-request-headers": "x-header-1, x-header-2",
					},
				},
				// Set the expected request properties and namespace to empty strings.
				// This is a workaround to avoid the test failure.
				// The response body is empty because the request is a preflight request,
				// so we can't get the request properties from the echoserver.
				ExpectedRequest: &http.ExpectedRequest{
					Request: http.Request{
						Host:    "",
						Method:  "OPTIONS",
						Path:    "",
						Headers: nil,
					},
				},
				Namespace: "",
				Response: http.Response{
					StatusCodes: []int{200, 204},
					ValidHeaderValues: map[string][]string{
						"access-control-allow-origin": {"https://other.foo.com", "*"},
						"access-control-allow-methods": {
							"PUT",
							"*",
						},
						"access-control-allow-headers": {
							"x-header-1, x-header-2",
							"x-header-2, x-header-1",
							"*",
						},
					},
					AbsentHeaders: []string{
						"access-control-allow-credentials",
					},
					// Ignore whitespace when comparing the response headers. This is because some
					// implementations add a space after each comma, and some don't. Both are valid.
					IgnoreWhitespace: true,
				},
			},
			{
				TestCaseName: "CORS request with credentials auth should be allowed and always echo the origin",
				Request: http.Request{
					Path:   "/cors-wildcard-methods-headers",
					Method: "GET",
					Headers: map[string]string{
						"Origin": "https://other.foo.com",
						"Cookie": "foo=bar", // Cookie is a credential.
					},
				},
				Namespace: ns,
				Response: http.Response{
					StatusCode: 200,
					ValidHeaderValues: map[string][]string{
						"access-control-allow-origin":      {"https://other.foo.com"},
						"access-control-allow-credentials": {"true"},
					},
				},
			},
			{
				TestCaseName: "CORS request with credentials should hide auth headers on unauth path",
				Request: http.Request{
					Path:   "/cors-wildcard-methods-headers-unauth",
					Method: "GET",
					Headers: map[string]string{
						"Origin": "https://other.foo.com",
						"Cookie": "foo=bar", // Cookie is a credential.
					},
				},
				Namespace: ns,
				Response: http.Response{
					StatusCode: 200,
					ValidHeaderValues: map[string][]string{
						"access-control-allow-origin": {"https://other.foo.com"},
					},
					AbsentHeaders: []string{
						"access-control-allow-credentials",
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
			})
		}
	},
}
