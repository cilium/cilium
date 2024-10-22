// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package routechecks

import metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

func merge(existingConditions []metav1.Condition, updates ...metav1.Condition) []metav1.Condition {
	var additions []metav1.Condition
	for i, update := range updates {
		found := false
		for j, cond := range existingConditions {
			if cond.Type == update.Type {
				found = true
				if conditionChanged(cond, update) {
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

func conditionChanged(a, b metav1.Condition) bool {
	return a.Status != b.Status ||
		a.Reason != b.Reason ||
		a.Message != b.Message ||
		a.ObservedGeneration != b.ObservedGeneration
}
