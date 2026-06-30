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

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
	"sigs.k8s.io/gateway-api/conformance/utils/kubernetes"
	"sigs.k8s.io/gateway-api/conformance/utils/suite"
	"sigs.k8s.io/gateway-api/pkg/features"
)

func init() {
	ConformanceTests = append(ConformanceTests, GatewayInvalidParametersRef)
}

var GatewayInvalidParametersRef = suite.ConformanceTest{
	ShortName:   "GatewayInvalidParametersRef",
	Description: "A Gateway referencing an invalid or non-existent parametersRef should set the Accepted condition to False with reason InvalidParameters.",
	Features: []features.FeatureName{
		features.SupportGateway,
	},
	Manifests: []string{"tests/gateway-invalid-parameters-ref.yaml"},
	Parallel:  true,
	Test: func(t *testing.T, s *suite.ConformanceTestSuite) {
		gwNN := types.NamespacedName{Name: "gateway-invalid-parameters-ref", Namespace: suite.InfrastructureNamespace}

		kubernetes.GatewayMustHaveLatestConditions(t, s.Client, s.TimeoutConfig, gwNN)
		kubernetes.GatewayMustHaveCondition(t, s.Client, s.TimeoutConfig, gwNN, metav1.Condition{
			Type:   string(gatewayv1.GatewayConditionAccepted),
			Status: metav1.ConditionFalse,
			Reason: string(gatewayv1.GatewayReasonInvalidParameters),
		})
	},
}
