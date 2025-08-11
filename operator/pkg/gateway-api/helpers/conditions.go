// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package helpers

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func IsConditionPresent(conds []metav1.Condition, condType string) bool {
	for _, cond := range conds {
		if cond.Type == condType {
			return true
		}
	}

	return false
}
