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
	ConformanceTests = append(ConformanceTests, ListenerSetReferenceGrant)
}

var ListenerSetReferenceGrant = suite.ConformanceTest{
	ShortName:   "ListenerSetReferenceGrant",
	Description: "ListenerSet with reference grant support",
	Features: []features.FeatureName{
		features.SupportGateway,
		features.SupportListenerSet,
		features.SupportReferenceGrant,
	},
	Manifests: []string{
		"tests/listenerset-reference-grant.yaml",
	},
	Test: func(t *testing.T, suite *suite.ConformanceTestSuite) {
		ns := "gateway-conformance-infra"

		kubernetes.NamespacesMustBeReady(t, suite.Client, suite.TimeoutConfig, []string{ns})

		// Verify the gateway is accepted
		gwNN := types.NamespacedName{Name: "gateway-with-listener-sets-test-reference-grant", Namespace: ns}
		kubernetes.GatewayMustHaveCondition(t, suite.Client, suite.TimeoutConfig, gwNN, metav1.Condition{
			Type:   string(gatewayv1.GatewayConditionAccepted),
			Status: metav1.ConditionTrue,
		})
		// Explicitly don't check the count here as implementations might differ on how to handle missing reference grants
		// kubernetes.GatewayMustHaveAttachedListeners(t, suite.Client, suite.TimeoutConfig, gwNN, 1)

		refPermittedCondition := []metav1.Condition{{
			Type:   string(gatewayv1.ListenerConditionResolvedRefs),
			Status: metav1.ConditionTrue,
			Reason: "", // any reason
		}}
		refNotPermittedCondition := []metav1.Condition{{
			Type:   string(gatewayv1.ListenerConditionResolvedRefs),
			Status: metav1.ConditionFalse,
			Reason: string(gatewayv1.ListenerReasonRefNotPermitted),
		}}

		// listenerset-with-reference-grant is accepted with the appropriate conditions
		lsNN := types.NamespacedName{Name: "listenerset-with-reference-grant", Namespace: ns}
		kubernetes.ListenerSetMustHaveCondition(t, suite.Client, suite.TimeoutConfig, lsNN, metav1.Condition{
			Type:   string(gatewayv1.ListenerSetConditionAccepted),
			Status: metav1.ConditionTrue,
			Reason: "", // any reason
		})
		kubernetes.ListenerSetMustHaveCondition(t, suite.Client, suite.TimeoutConfig, lsNN, metav1.Condition{
			Type:   string(gatewayv1.ListenerSetConditionProgrammed),
			Status: metav1.ConditionTrue,
			Reason: "", // any reason
		})
		kubernetes.ListenerSetListenersMustHaveConditions(t, suite.Client, suite.TimeoutConfig, lsNN, refPermittedCondition, "listenerset-with-reference-grant-listener")

		// listenerset-without-reference-grant is not accepted because the only listener is missing a reference grant
		lsNN = types.NamespacedName{Name: "listenerset-without-reference-grant", Namespace: "gateway-api-listener-sets-test-reference-grant-ns"}
		kubernetes.ListenerSetMustHaveCondition(t, suite.Client, suite.TimeoutConfig, lsNN, metav1.Condition{
			Type:   string(gatewayv1.ListenerSetConditionAccepted),
			Status: metav1.ConditionFalse,
			Reason: string(gatewayv1.ListenerSetReasonListenersNotValid),
		})
		kubernetes.ListenerSetMustHaveCondition(t, suite.Client, suite.TimeoutConfig, lsNN, metav1.Condition{
			Type:   string(gatewayv1.ListenerSetConditionProgrammed),
			Status: metav1.ConditionFalse,
			Reason: string(gatewayv1.ListenerSetReasonListenersNotValid),
		})
		kubernetes.ListenerSetListenersMustHaveConditions(t, suite.Client, suite.TimeoutConfig, lsNN, refNotPermittedCondition, "listenerset-without-reference-grant-listener")
	},
}
