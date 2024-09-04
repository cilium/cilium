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
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	"sigs.k8s.io/gateway-api/apis/v1beta1"
	"sigs.k8s.io/gateway-api/conformance/utils/http"
	"sigs.k8s.io/gateway-api/conformance/utils/kubernetes"
	"sigs.k8s.io/gateway-api/conformance/utils/suite"
	"sigs.k8s.io/gateway-api/pkg/features"
)

func init() {
	ConformanceTests = append(ConformanceTests, HTTPRouteReferenceGrant)
}

var HTTPRouteReferenceGrant = suite.ConformanceTest{
	ShortName:   "HTTPRouteReferenceGrant",
	Description: "A single HTTPRoute in the gateway-conformance-infra namespace, with a backendRef in the gateway-conformance-web-backend namespace, should attach to Gateway in the gateway-conformance-infra namespace",
	Features: []features.FeatureName{
		features.SupportGateway,
		features.SupportHTTPRoute,
		features.SupportReferenceGrant,
	},
	Manifests: []string{"tests/httproute-reference-grant.yaml"},
	Test: func(t *testing.T, suite *suite.ConformanceTestSuite) {
		routeNN := types.NamespacedName{Name: "reference-grant", Namespace: "gateway-conformance-infra"}
		gwNN := types.NamespacedName{Name: "same-namespace", Namespace: "gateway-conformance-infra"}
		gwAddr := kubernetes.GatewayAndHTTPRoutesMustBeAccepted(t, suite.Client, suite.TimeoutConfig, suite.ControllerName, kubernetes.NewGatewayRef(gwNN), routeNN)
		kubernetes.HTTPRouteMustHaveResolvedRefsConditionsTrue(t, suite.Client, suite.TimeoutConfig, routeNN, gwNN)

		t.Run("Simple HTTP request should reach web-backend", func(t *testing.T) {
			http.MakeRequestAndExpectEventuallyConsistentResponse(t, suite.RoundTripper, suite.TimeoutConfig, gwAddr, http.ExpectedResponse{
				Request: http.Request{
					Method: "GET",
					Path:   "/",
				},
				Response:  http.Response{StatusCode: 200},
				Backend:   "web-backend",
				Namespace: "gateway-conformance-web-backend",
			})
		})

		ctx, cancel := context.WithTimeout(context.Background(), suite.TimeoutConfig.DeleteTimeout)
		defer cancel()
		rg := v1beta1.ReferenceGrant{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "reference-grant",
				Namespace: "gateway-conformance-web-backend",
			},
		}
		require.NoError(t, suite.Client.Delete(ctx, &rg))

		t.Run("Simple HTTP request should return 500 after deleting the relevant reference grant", func(t *testing.T) {
			http.MakeRequestAndExpectEventuallyConsistentResponse(t, suite.RoundTripper, suite.TimeoutConfig, gwAddr, http.ExpectedResponse{
				Request: http.Request{
					Method: "GET",
					Path:   "/",
				},
				Response: http.Response{StatusCode: 500},
			})
		})
	},
}
