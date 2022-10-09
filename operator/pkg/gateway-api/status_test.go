// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package gateway_api

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	gatewayv1beta1 "sigs.k8s.io/gateway-api/apis/v1beta1"
)

func Test_merge(t *testing.T) {
	now := time.Now()
	later := time.Now()

	testCases := []struct {
		name     string
		current  []metav1.Condition
		updates  []metav1.Condition
		expected []metav1.Condition
	}{
		{
			name: "status updated",
			current: []metav1.Condition{
				newCondition("Ready", metav1.ConditionFalse, "Reason", "Message", now, 1),
			},
			updates: []metav1.Condition{
				newCondition("Ready", metav1.ConditionTrue, "Reason", "Message", later, 1),
			},
			expected: []metav1.Condition{
				newCondition("Ready", metav1.ConditionTrue, "Reason", "Message", later, 1),
			},
		},
		{
			name: "reason updated",
			current: []metav1.Condition{
				newCondition("Ready", metav1.ConditionFalse, "Reason", "Message", now, 1),
			},
			updates: []metav1.Condition{
				newCondition("Ready", metav1.ConditionFalse, "New Reason", "Message", now, 1),
			},
			expected: []metav1.Condition{
				newCondition("Ready", metav1.ConditionFalse, "New Reason", "Message", now, 1),
			},
		},
		{
			name: "message updated",
			current: []metav1.Condition{
				newCondition("Ready", metav1.ConditionFalse, "Reason", "Message", now, 1),
			},
			updates: []metav1.Condition{
				newCondition("Ready", metav1.ConditionFalse, "Reason", "New Message", now, 1),
			},
			expected: []metav1.Condition{
				newCondition("Ready", metav1.ConditionFalse, "Reason", "New Message", now, 1),
			},
		},
		{
			name: "new condition",
			current: []metav1.Condition{
				newCondition("Ready", metav1.ConditionFalse, "Reason", "Message", now, 1),
			},
			updates: []metav1.Condition{
				newCondition("Accepted", metav1.ConditionTrue, "Reason", "Another Message", now, 1),
			},
			expected: []metav1.Condition{
				newCondition("Ready", metav1.ConditionFalse, "Reason", "Message", now, 1),
				newCondition("Accepted", metav1.ConditionTrue, "Reason", "Another Message", now, 1),
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got := merge(tc.current, tc.updates...)
			if conditionChanged(tc.expected[0], got[0]) {
				assert.Equal(t, tc.expected, got, tc.name)
			}
		})
	}
}

func Test_conditionChanged(t *testing.T) {
	testCases := []struct {
		name     string
		expected bool
		a, b     metav1.Condition
	}{
		{
			name:     "nil and non-nil current are equal",
			expected: false,
			a:        metav1.Condition{},
		},
		{
			name:     "empty slices should be equal",
			expected: false,
			a:        metav1.Condition{},
			b:        metav1.Condition{},
		},
		{
			name:     "condition LastTransitionTime should be ignored",
			expected: false,
			a: metav1.Condition{
				Type:               string(gatewayv1beta1.GatewayClassConditionStatusAccepted),
				Status:             metav1.ConditionTrue,
				LastTransitionTime: metav1.Unix(0, 0),
			},
			b: metav1.Condition{
				Type:               string(gatewayv1beta1.GatewayClassConditionStatusAccepted),
				Status:             metav1.ConditionTrue,
				LastTransitionTime: metav1.Unix(1, 0),
			},
		},
		{
			name:     "check condition reason differs",
			expected: true,
			a: metav1.Condition{
				Type:   string(gatewayv1beta1.GatewayConditionReady),
				Status: metav1.ConditionFalse,
				Reason: "foo",
			},
			b: metav1.Condition{
				Type:   string(gatewayv1beta1.GatewayConditionReady),
				Status: metav1.ConditionFalse,
				Reason: "bar",
			},
		},
		{
			name:     "condition status differs",
			expected: true,
			a: metav1.Condition{
				Type:   string(gatewayv1beta1.GatewayClassConditionStatusAccepted),
				Status: metav1.ConditionTrue,
			},
			b: metav1.Condition{
				Type:   string(gatewayv1beta1.GatewayClassConditionStatusAccepted),
				Status: metav1.ConditionFalse,
			},
		},
		{
			name:     "observed generation differs",
			expected: true,
			a: metav1.Condition{
				Type:               string(gatewayv1beta1.GatewayClassConditionStatusAccepted),
				ObservedGeneration: 1,
			},
			b: metav1.Condition{
				Type:               string(gatewayv1beta1.GatewayClassConditionStatusAccepted),
				ObservedGeneration: 2,
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			res := conditionChanged(tc.a, tc.b)
			assert.Equal(t, tc.expected, res)
		})
	}
}

// findConditionInList finds a condition in a list of Conditions, checking
// the Name, Value, and Reason. If an empty reason is passed, any Reason will match.
func findConditionInList(t *testing.T, conditions []metav1.Condition, condName, condValue, condReason string) bool {
	for _, cond := range conditions {
		if cond.Type == condName {
			if cond.Status == metav1.ConditionStatus(condValue) {
				// an empty Reason string means "Match any reason".
				if condReason == "" || cond.Reason == condReason {
					return true
				}
				t.Logf("%s condition Reason set to %s, expected %s", condName, cond.Reason, condReason)
			}

			t.Logf("%s condition set to %s, expected %s", condName, cond.Status, condValue)
		}
	}

	t.Logf("%s was not in conditions list", condName)
	return false
}
