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

	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"

	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
	"sigs.k8s.io/gateway-api/conformance/utils/http"
	"sigs.k8s.io/gateway-api/conformance/utils/kubernetes"
	confsuite "sigs.k8s.io/gateway-api/conformance/utils/suite"
	"sigs.k8s.io/gateway-api/pkg/features"
)

func init() {
	ConformanceTests = append(ConformanceTests, ListenerSetGatewayParentSectionNameNotFound)
}

var ListenerSetGatewayParentSectionNameNotFound = confsuite.ConformanceTest{
	ShortName:   "ListenerSetGatewayParentSectionNameNotFound",
	Description: "A Route must not be able to find a ListenerSet sectionName using a Gateway parentRef",
	Features: []features.FeatureName{
		features.SupportGateway,
		features.SupportListenerSet,
		features.SupportHTTPRoute,
	},
	Manifests: []string{
		"tests/listenerset-gateway-parent-section-name-not-found.yaml",
	},
	Test: func(t *testing.T, suite *confsuite.ConformanceTestSuite) {
		ns := confsuite.InfrastructureNamespace
		kubernetes.NamespacesMustBeReady(t, suite.Client, suite.TimeoutConfig, []string{ns})

		gwNN := types.NamespacedName{Name: "gateway-section-name", Namespace: ns}
		gwAddr, err := kubernetes.WaitForGatewayAddress(t, suite.Client, suite.TimeoutConfig, kubernetes.NewGatewayRef(gwNN, "gw-listener"))
		require.NoErrorf(t, err, "timed out waiting for Gateway address to be assigned")
		kubernetes.GatewayMustHaveCondition(t, suite.Client, suite.TimeoutConfig, gwNN, metav1.Condition{
			Type:   string(gatewayv1.GatewayConditionAccepted),
			Status: metav1.ConditionTrue,
		})
		kubernetes.GatewayMustHaveAttachedListeners(t, suite.Client, suite.TimeoutConfig, gwNN, 1)

		listenerSetGK := schema.GroupKind{
			Group: gatewayv1.GroupVersion.Group,
			Kind:  "ListenerSet",
		}
		lsNN := types.NamespacedName{Name: "listenerset-section-name", Namespace: ns}
		listenerSetRef := kubernetes.NewResourceRef(listenerSetGK, lsNN)

		kubernetes.RoutesAndParentMustBeAccepted(t, suite.Client, suite.TimeoutConfig, suite.ControllerName, listenerSetRef, &gatewayv1.HTTPRoute{},
			types.NamespacedName{Name: "route-via-listenerset", Namespace: ns})

		kubernetes.HTTPRouteMustHaveCondition(t, suite.Client, suite.TimeoutConfig,
			types.NamespacedName{Name: "route-via-gateway", Namespace: ns},
			gwNN,
			metav1.Condition{
				Type:   string(gatewayv1.RouteConditionAccepted),
				Status: metav1.ConditionFalse,
				Reason: string(gatewayv1.RouteReasonNoMatchingParent),
			})

		http.MakeRequestAndExpectEventuallyConsistentResponse(t, suite.RoundTripper, suite.TimeoutConfig, gwAddr,
			http.ExpectedResponse{
				Request:   http.Request{Host: "ls-section-name.com", Path: "/goodsection"},
				Backend:   confsuite.InfraBackendServiceNameV1,
				Namespace: ns,
			})

		http.MakeRequestAndExpectEventuallyConsistentResponse(t, suite.RoundTripper, suite.TimeoutConfig, gwAddr,
			http.ExpectedResponse{
				Request:  http.Request{Host: "gw-section.com", Path: "/badsection"},
				Response: http.Response{StatusCode: 404},
			})
	},
}
