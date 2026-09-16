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

package tests

import (
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
	"sigs.k8s.io/gateway-api/conformance/utils/suite"
	gatewayfeatures "sigs.k8s.io/gateway-api/pkg/features"

	"sigs.k8s.io/gateway-api-inference-extension/conformance/resources"
	"sigs.k8s.io/gateway-api-inference-extension/conformance/utils/features"
	k8sutils "sigs.k8s.io/gateway-api-inference-extension/conformance/utils/kubernetes"
)

func init() {
	ConformanceTests = append(ConformanceTests, InferencePoolAccepted)
}

// InferencePoolAccepted defines the test case for verifying basic InferencePool acceptance.
var InferencePoolAccepted = suite.ConformanceTest{
	ShortName:   "InferencePoolAccepted",
	Description: "A minimal InferencePool resource should be accepted by the controller and report an Accepted condition",
	Manifests:   []string{"tests/inferencepool_accepted.yaml"},
	Features: []gatewayfeatures.FeatureName{
		features.SupportInferencePool,
		gatewayfeatures.SupportGateway,
	},
	Test: func(t *testing.T, s *suite.ConformanceTestSuite) {
		poolNN := resources.PrimaryInferencePoolNN
		gatewayNN := resources.PrimaryGatewayNN

		t.Run("InferencePool should have Accepted condition set to True", func(t *testing.T) {
			acceptedCondition := metav1.Condition{
				Type:   string(gatewayv1.GatewayConditionAccepted),
				Status: metav1.ConditionTrue,
				Reason: "", // "" means we don't strictly check the Reason for this basic test.
			}
			k8sutils.InferencePoolMustHaveCondition(t, s.Client, poolNN, gatewayNN, acceptedCondition)
		})
	},
}
