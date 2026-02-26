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
	"k8s.io/apimachinery/pkg/types"

	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
	"sigs.k8s.io/gateway-api/conformance/utils/kubernetes"
	"sigs.k8s.io/gateway-api/conformance/utils/suite"
	"sigs.k8s.io/gateway-api/pkg/features"
)

func init() {
	ConformanceTests = append(ConformanceTests, ListenerSetAllowedNamespaceNone)
}

var ListenerSetAllowedNamespaceNone = suite.ConformanceTest{
	ShortName:   "ListenerSetAllowedNamespaceNone",
	Description: "Listener Sets are not allowed on the Gateway when `allowedListeners` is set to `None`",
	Features: []features.FeatureName{
		features.SupportGateway,
		features.SupportListenerSet,
	},
	Manifests: []string{
		"tests/listenerset-allowed-namespace-none.yaml",
	},
	Test: func(t *testing.T, suite *suite.ConformanceTestSuite) {
		ns := "gateway-conformance-infra"
		kubernetes.NamespacesMustBeReady(t, suite.Client, suite.TimeoutConfig, []string{ns})

		// Verify the gateway is accepted
		gwNN := types.NamespacedName{Name: "gateway-does-not-allow-listenerset", Namespace: ns}
		kubernetes.GatewayMustHaveCondition(t, suite.Client, suite.TimeoutConfig, gwNN, metav1.Condition{
			Type:   string(gatewayv1.GatewayConditionAccepted),
			Status: metav1.ConditionTrue,
		})
		// Rejected ListenerSets :
		// - gateway-conformance-infra/listenerset-not-allowed - the gateway is not configured to allow listenerSets
		kubernetes.GatewayMustHaveAttachedListeners(t, suite.Client, suite.TimeoutConfig, gwNN, 0)

		// Verify that listenerset-not-allowed is rejected with the `ListenerSetReasonNotAllowed` condition
		disallowedLsNN := types.NamespacedName{Name: "listenerset-not-allowed", Namespace: ns}
		kubernetes.ListenerSetMustHaveCondition(t, suite.Client, suite.TimeoutConfig, disallowedLsNN, metav1.Condition{
			Type:   string(gatewayv1.ListenerSetConditionAccepted),
			Status: metav1.ConditionFalse,
			Reason: string(gatewayv1.ListenerSetReasonNotAllowed),
		})
		kubernetes.ListenerSetMustHaveCondition(t, suite.Client, suite.TimeoutConfig, disallowedLsNN, metav1.Condition{
			Type:   string(gatewayv1.ListenerSetConditionProgrammed),
			Status: metav1.ConditionFalse,
			Reason: string(gatewayv1.ListenerSetReasonNotAllowed),
		})
	},
}
