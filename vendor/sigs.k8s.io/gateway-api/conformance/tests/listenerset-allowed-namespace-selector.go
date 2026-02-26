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
	ConformanceTests = append(ConformanceTests, ListenerSetAllowedNamespaceSelector)
}

var ListenerSetAllowedNamespaceSelector = suite.ConformanceTest{
	ShortName:   "ListenerSetAllowedNamespaceSelector",
	Description: "ListenerSets in the namespaces that match the labels are allowed when `allowedListeners` is set to `Selector`",
	Features: []features.FeatureName{
		features.SupportGateway,
		features.SupportListenerSet,
	},
	Manifests: []string{
		"tests/listenerset-allowed-namespace-selector.yaml",
	},
	Test: func(t *testing.T, suite *suite.ConformanceTestSuite) {
		ns := "gateway-conformance-infra"
		kubernetes.NamespacesMustBeReady(t, suite.Client, suite.TimeoutConfig, []string{ns})

		// Verify the gateway is accepted
		gwNN := types.NamespacedName{Name: "gateway-allows-listenerset-in-selected-namespace", Namespace: ns}
		kubernetes.GatewayMustHaveCondition(t, suite.Client, suite.TimeoutConfig, gwNN, metav1.Condition{
			Type:   string(gatewayv1.GatewayConditionAccepted),
			Status: metav1.ConditionTrue,
		})
		// Accepted ListenerSets :
		// - gateway-api-listenerset-selector-allowed-ns/listenerset-in-selected-namespace - it is in the namespace that matches the label selector defined in `allowedListeners`
		// Rejected ListenerSets :
		// - gateway-api-listenerset-selector-not-allowed-ns/listenerset-not-in-selected-namespace - it is not in the namespace that matches the label selector defined in `allowedListeners`
		kubernetes.GatewayMustHaveAttachedListeners(t, suite.Client, suite.TimeoutConfig, gwNN, 1)

		// Verify the accepted listenerSet has the appropriate conditions
		lsNN := types.NamespacedName{Name: "listenerset-in-selected-namespace", Namespace: "gateway-api-listenerset-selector-allowed-ns"}
		kubernetes.ListenerSetMustHaveCondition(t, suite.Client, suite.TimeoutConfig, lsNN, metav1.Condition{
			Type:   string(gatewayv1.ListenerSetConditionAccepted),
			Status: metav1.ConditionTrue,
			Reason: string(gatewayv1.ListenerSetReasonAccepted),
		})
		kubernetes.ListenerSetMustHaveCondition(t, suite.Client, suite.TimeoutConfig, lsNN, metav1.Condition{
			Type:   string(gatewayv1.ListenerSetConditionProgrammed),
			Status: metav1.ConditionTrue,
			Reason: string(gatewayv1.ListenerSetReasonProgrammed),
		})
		kubernetes.ListenerSetListenersMustHaveConditions(t, suite.Client, suite.TimeoutConfig, lsNN, generateAcceptedListenerConditions(), "listenerset-in-selected-namespace-listener")

		// Verify the rejected listenerSet has the appropriate conditions
		disallowedLsNN := types.NamespacedName{Name: "listenerset-not-in-selected-namespace", Namespace: "gateway-api-listenerset-selector-not-allowed-ns"}
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
