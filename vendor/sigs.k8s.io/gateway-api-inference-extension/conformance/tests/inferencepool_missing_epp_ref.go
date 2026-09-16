/*
Copyright 2026 The Kubernetes Authors.

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

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
	"sigs.k8s.io/gateway-api/conformance/utils/kubernetes"
	"sigs.k8s.io/gateway-api/conformance/utils/suite"
	gatewayfeatures "sigs.k8s.io/gateway-api/pkg/features"

	inferenceapi "sigs.k8s.io/gateway-api-inference-extension/api/v1"
	"sigs.k8s.io/gateway-api-inference-extension/conformance/resources"
	"sigs.k8s.io/gateway-api-inference-extension/conformance/utils/features"
	k8sutils "sigs.k8s.io/gateway-api-inference-extension/conformance/utils/kubernetes"
)

func init() {
	ConformanceTests = append(ConformanceTests, InferencePoolMissingEPPRef)
}

var InferencePoolMissingEPPRef = suite.ConformanceTest{
	ShortName:   "InferencePoolMissingEPPRef",
	Description: "An HTTPRoute that references an InferencePool with endpointPickerRef unspecified should have Accepted condition with status True. The InferencePool should either have Accepted condition with status True or with status False and reason EndpointPickerRefMissing",
	Manifests:   []string{"tests/inferencepool_missing_epp_ref.yaml"},
	Features: []gatewayfeatures.FeatureName{
		gatewayfeatures.SupportGateway,
		gatewayfeatures.SupportHTTPRoute,
		features.SupportInferencePool,
	},
	Test: func(t *testing.T, s *suite.ConformanceTestSuite) {
		const routePath = "/missing-epp-ref-test"

		routeNN := types.NamespacedName{Name: "httproute-for-missing-epp-ref-pool", Namespace: resources.AppBackendNamespace}
		gwNN := resources.PrimaryGatewayNN
		poolNN := types.NamespacedName{Name: "pool-with-missing-epp-ref", Namespace: resources.AppBackendNamespace}

		httpRouteAcceptedCondition := metav1.Condition{
			Type:   string(gatewayv1.RouteConditionAccepted),
			Status: metav1.ConditionTrue,
			Reason: string(gatewayv1.RouteReasonAccepted),
		}
		kubernetes.HTTPRouteMustHaveCondition(t, s.Client, s.TimeoutConfig, routeNN, gwNN, httpRouteAcceptedCondition)
		t.Run("InferencePool has Accepted condition with status True or reason EndpointPickerRefMissing", func(t *testing.T) {
			allowedConditions := []metav1.Condition{
				{
					Type:   string(inferenceapi.InferencePoolConditionAccepted),
					Status: metav1.ConditionTrue,
				},
				{
					Type:   string(inferenceapi.InferencePoolConditionAccepted),
					Status: metav1.ConditionFalse,
					Reason: string(inferenceapi.InferencePoolReasonEndpointPickerRefMissing),
				},
			}
			k8sutils.InferencePoolMustHaveOneOfConditions(t, s.Client, poolNN, gwNN, allowedConditions)
		})
	},
}
