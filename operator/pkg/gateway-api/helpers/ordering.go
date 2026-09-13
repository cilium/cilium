// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package helpers

import (
	"cmp"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// CompareByCreationTimestampAndObjectKey compares two Kubernetes objects by
// their object metadata following the Gateway API conflict resolution rules:
// the object with the oldest creation timestamp sorts first, and objects with
// equal creation timestamps are ordered by namespace and then by name.
//
// Namespace and name are compared as separate fields rather than as a joined
// "namespace/name" string: '-' (0x2D) sorts below '/' (0x2F), so the joined
// form would give a namespace that is a prefix of another precedence based on
// the separator (e.g. "a-x/b" would sort before "a/c").
func CompareByCreationTimestampAndObjectKey(a, b metav1.ObjectMeta) int {
	if c := a.CreationTimestamp.Time.Compare(b.CreationTimestamp.Time); c != 0 {
		return c
	}
	if c := cmp.Compare(a.Namespace, b.Namespace); c != 0 {
		return c
	}
	return cmp.Compare(a.Name, b.Name)
}
