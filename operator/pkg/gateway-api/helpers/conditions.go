// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package helpers

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

func IsConditionPresent(conds []metav1.Condition, condType string) bool {
	for _, cond := range conds {
		if cond.Type == condType {
			return true
		}
	}

	return false
}

func MergeConditions(existingConditions []metav1.Condition, updates ...metav1.Condition) []metav1.Condition {
	var additions []metav1.Condition
	for i, update := range updates {
		found := false
		for j, cond := range existingConditions {
			if cond.Type == update.Type {
				found = true
				if ConditionChanged(cond, update) {
					existingConditions[j].Status = update.Status
					existingConditions[j].Reason = update.Reason
					existingConditions[j].Message = update.Message
					existingConditions[j].ObservedGeneration = update.ObservedGeneration
					existingConditions[j].LastTransitionTime = update.LastTransitionTime
				}
				break
			}
		}
		if !found {
			additions = append(additions, updates[i])
		}
	}
	existingConditions = append(existingConditions, additions...)
	return existingConditions
}

func ConditionChanged(a, b metav1.Condition) bool {
	return a.Status != b.Status ||
		a.Reason != b.Reason ||
		a.Message != b.Message ||
		a.ObservedGeneration != b.ObservedGeneration
}

func IsAccepted(conds []metav1.Condition) bool {
	for _, cond := range conds {
		if cond.Type == string(gatewayv1.GatewayConditionAccepted) && cond.Status == metav1.ConditionTrue {
			return true
		}
	}

	return false
}
