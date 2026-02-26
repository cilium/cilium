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
	ConformanceTests = append(ConformanceTests, ListenerSetHostnameConflict)
}

var ListenerSetHostnameConflict = suite.ConformanceTest{
	ShortName:   "ListenerSetHostnameConflict",
	Description: "Validate Listener Precedence when a ListenerSet listener has a hostname conflict",
	Features: []features.FeatureName{
		features.SupportGateway,
		features.SupportListenerSet,
	},
	Manifests: []string{
		"tests/listenerset-hostname-conflict.yaml",
	},
	Test: func(t *testing.T, suite *suite.ConformanceTestSuite) {
		ns := "gateway-conformance-infra"
		kubernetes.NamespacesMustBeReady(t, suite.Client, suite.TimeoutConfig, []string{ns})

		hostnameConflictedListenerConditions := []metav1.Condition{
			{
				Type:   string(gatewayv1.ListenerConditionAccepted),
				Status: metav1.ConditionFalse,
				Reason: string(gatewayv1.ListenerReasonHostnameConflict),
			},
			{
				Type:   string(gatewayv1.ListenerConditionProgrammed),
				Status: metav1.ConditionFalse,
				Reason: string(gatewayv1.ListenerReasonHostnameConflict),
			},
			{
				Type:   string(gatewayv1.ListenerConditionConflicted),
				Status: metav1.ConditionTrue,
				Reason: string(gatewayv1.ListenerReasonHostnameConflict),
			},
		}

		// Verify the gateway is accepted
		gwNN := types.NamespacedName{Name: "gateway-with-listenerset-hostname-conflict", Namespace: ns}
		kubernetes.GatewayMustHaveCondition(t, suite.Client, suite.TimeoutConfig, gwNN, metav1.Condition{
			Type:   string(gatewayv1.GatewayConditionAccepted),
			Status: metav1.ConditionTrue,
		})
		kubernetes.GatewayListenersMustHaveConditions(t, suite.Client, suite.TimeoutConfig, gwNN, generateAcceptedListenerConditions(), "gateway-listener")
		// The first conflicted listener is accepted based on Listener precedence
		kubernetes.GatewayListenersMustHaveConditions(t, suite.Client, suite.TimeoutConfig, gwNN, generateAcceptedListenerConditions(), "hostname-conflict-with-gateway-listener")
		// The following listenerSets are accepted since they have at least one valid listener :
		// - listenerset-with-hostname-conflict-with-gateway-1
		// - listenerset-with-hostname-conflict-with-listener-set-1
		// The following listenerSets are not accepted since they do not have at least one valid listener :
		// - listenerset-with-hostname-conflict-with-gateway-2
		// - listenerset-with-hostname-conflict-with-listener-set-2
		kubernetes.GatewayMustHaveAttachedListeners(t, suite.Client, suite.TimeoutConfig, gwNN, 2)

		// listenerset-with-hostname-conflict-with-gateway-1 is accepted since it has at least one valid listener
		lsNN := types.NamespacedName{Name: "listenerset-with-hostname-conflict-with-gateway-1", Namespace: ns}
		kubernetes.ListenerSetMustHaveCondition(t, suite.Client, suite.TimeoutConfig, lsNN, metav1.Condition{
			Type:   string(gatewayv1.ListenerSetConditionAccepted),
			Status: metav1.ConditionTrue,
			Reason: "", // any reason
		})
		kubernetes.ListenerSetMustHaveCondition(t, suite.Client, suite.TimeoutConfig, lsNN, metav1.Condition{
			Type:   string(gatewayv1.ListenerSetConditionProgrammed),
			Status: metav1.ConditionTrue,
			Reason: string(gatewayv1.ListenerSetReasonProgrammed),
		})
		kubernetes.ListenerSetListenersMustHaveConditions(t, suite.Client, suite.TimeoutConfig, lsNN, generateAcceptedListenerConditions(), "listener-set-1-listener")
		// The conflicted listener should not be accepted
		kubernetes.ListenerSetListenersMustHaveConditions(t, suite.Client, suite.TimeoutConfig, lsNN, hostnameConflictedListenerConditions, "hostname-conflict-with-gateway-listener")
		// The first conflicted listener is accepted based on Listener precedence
		kubernetes.ListenerSetListenersMustHaveConditions(t, suite.Client, suite.TimeoutConfig, lsNN, generateAcceptedListenerConditions(), "hostname-conflict-with-listener-set-listener")

		// listenerset-with-hostname-conflict-with-gateway-2 is not accepted since it does not have at least one valid listener
		lsNN = types.NamespacedName{Name: "listenerset-with-hostname-conflict-with-gateway-2", Namespace: ns}
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
		// The conflicted listener should not be accepted
		kubernetes.ListenerSetListenersMustHaveConditions(t, suite.Client, suite.TimeoutConfig, lsNN, hostnameConflictedListenerConditions, "hostname-conflict-with-gateway-listener")

		// listenerset-with-hostname-conflict-with-listener-set-1 is accepted since it has at least one valid listener
		lsNN = types.NamespacedName{Name: "listenerset-with-hostname-conflict-with-listener-set-1", Namespace: ns}
		kubernetes.ListenerSetMustHaveCondition(t, suite.Client, suite.TimeoutConfig, lsNN, metav1.Condition{
			Type:   string(gatewayv1.ListenerSetConditionAccepted),
			Status: metav1.ConditionTrue,
			Reason: "", // any reason
		})
		kubernetes.ListenerSetMustHaveCondition(t, suite.Client, suite.TimeoutConfig, lsNN, metav1.Condition{
			Type:   string(gatewayv1.ListenerSetConditionProgrammed),
			Status: metav1.ConditionTrue,
			Reason: string(gatewayv1.ListenerSetReasonProgrammed),
		})
		kubernetes.ListenerSetListenersMustHaveConditions(t, suite.Client, suite.TimeoutConfig, lsNN, generateAcceptedListenerConditions(), "listener-set-2-listener")
		// The conflicted listener should not be accepted
		kubernetes.ListenerSetListenersMustHaveConditions(t, suite.Client, suite.TimeoutConfig, lsNN, hostnameConflictedListenerConditions, "hostname-conflict-with-listener-set-listener")

		// listenerset-with-hostname-conflict-with-listener-set-2 is not accepted since it does not have at least one valid listener
		lsNN = types.NamespacedName{Name: "listenerset-with-hostname-conflict-with-listener-set-2", Namespace: ns}
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
		// The conflicted listener should not be accepted
		kubernetes.ListenerSetListenersMustHaveConditions(t, suite.Client, suite.TimeoutConfig, lsNN, hostnameConflictedListenerConditions, "hostname-conflict-with-listener-set-listener")
	},
}
