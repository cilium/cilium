// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package helpers

import (
	"cmp"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// CompareCreationTimeThenNamespacedName compares objects metadata by creation
// timestamp (older wins), breaking ties by alphabetically ordered namespace and then name.
func CompareCreationTimeThenNamespacedName(a, b metav1.ObjectMeta) int {
	if c := a.CreationTimestamp.Time.Compare(b.CreationTimestamp.Time); c != 0 {
		return c
	}

	if c := cmp.Compare(a.Namespace, b.Namespace); c != 0 {
		return c
	}

	return cmp.Compare(a.Name, b.Name)
}
