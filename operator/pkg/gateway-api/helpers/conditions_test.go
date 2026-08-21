// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package helpers

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

func testCondition(conditionType string, status metav1.ConditionStatus, reason, msg string, lastTransitionTime time.Time, observedGeneration int64) metav1.Condition {
	return metav1.Condition{
		Type:               conditionType,
		Status:             status,
		Reason:             reason,
		Message:            msg,
		LastTransitionTime: metav1.NewTime(lastTransitionTime),
		ObservedGeneration: observedGeneration,
	}
}

func TestMergeConditions(t *testing.T) {
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
				testCondition("Ready", metav1.ConditionFalse, "Reason", "Message", now, 1),
			},
			updates: []metav1.Condition{
				testCondition("Ready", metav1.ConditionTrue, "Reason", "Message", later, 1),
			},
			expected: []metav1.Condition{
				testCondition("Ready", metav1.ConditionTrue, "Reason", "Message", later, 1),
			},
		},
		{
			name: "reason updated",
			current: []metav1.Condition{
				testCondition("Ready", metav1.ConditionFalse, "Reason", "Message", now, 1),
			},
			updates: []metav1.Condition{
				testCondition("Ready", metav1.ConditionFalse, "New Reason", "Message", now, 1),
			},
			expected: []metav1.Condition{
				testCondition("Ready", metav1.ConditionFalse, "New Reason", "Message", now, 1),
			},
		},
		{
			name: "message updated",
			current: []metav1.Condition{
				testCondition("Ready", metav1.ConditionFalse, "Reason", "Message", now, 1),
			},
			updates: []metav1.Condition{
				testCondition("Ready", metav1.ConditionFalse, "Reason", "New Message", now, 1),
			},
			expected: []metav1.Condition{
				testCondition("Ready", metav1.ConditionFalse, "Reason", "New Message", now, 1),
			},
		},
		{
			name: "new condition",
			current: []metav1.Condition{
				testCondition("Ready", metav1.ConditionFalse, "Reason", "Message", now, 1),
			},
			updates: []metav1.Condition{
				testCondition("Accepted", metav1.ConditionTrue, "Reason", "Another Message", now, 1),
			},
			expected: []metav1.Condition{
				testCondition("Ready", metav1.ConditionFalse, "Reason", "Message", now, 1),
				testCondition("Accepted", metav1.ConditionTrue, "Reason", "Another Message", now, 1),
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got := MergeConditions(tc.current, tc.updates...)
			if ConditionChanged(tc.expected[0], got[0]) {
				assert.Equal(t, tc.expected, got, tc.name)
			}
		})
	}
}

func TestConditionChanged(t *testing.T) {
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
				Type:               string(gatewayv1.GatewayClassConditionStatusAccepted),
				Status:             metav1.ConditionTrue,
				LastTransitionTime: metav1.Unix(0, 0),
			},
			b: metav1.Condition{
				Type:               string(gatewayv1.GatewayClassConditionStatusAccepted),
				Status:             metav1.ConditionTrue,
				LastTransitionTime: metav1.Unix(1, 0),
			},
		},
		{
			name:     "check condition reason differs",
			expected: true,
			a: metav1.Condition{
				Type:   string(gatewayv1.GatewayConditionReady),
				Status: metav1.ConditionFalse,
				Reason: "foo",
			},
			b: metav1.Condition{
				Type:   string(gatewayv1.GatewayConditionReady),
				Status: metav1.ConditionFalse,
				Reason: "bar",
			},
		},
		{
			name:     "condition status differs",
			expected: true,
			a: metav1.Condition{
				Type:   string(gatewayv1.GatewayClassConditionStatusAccepted),
				Status: metav1.ConditionTrue,
			},
			b: metav1.Condition{
				Type:   string(gatewayv1.GatewayClassConditionStatusAccepted),
				Status: metav1.ConditionFalse,
			},
		},
		{
			name:     "observed generation differs",
			expected: true,
			a: metav1.Condition{
				Type:               string(gatewayv1.GatewayClassConditionStatusAccepted),
				ObservedGeneration: 1,
			},
			b: metav1.Condition{
				Type:               string(gatewayv1.GatewayClassConditionStatusAccepted),
				ObservedGeneration: 2,
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			res := ConditionChanged(tc.a, tc.b)
			assert.Equal(t, tc.expected, res)
		})
	}
}
