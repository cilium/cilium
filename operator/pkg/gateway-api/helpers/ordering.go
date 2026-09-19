// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package helpers

import (
	"cmp"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// CompareByCreationTimestampAndObjectKey puts the earlier-created object ahead;
// when both timestamps match, the namespace decides, then the name.
//
// The two keys stay independent instead of being stitched into one
// "namespace/name" string. Stitching lets punctuation reshuffle the result:
// '-' ranks ahead of '/', so "a-x/b" would outrank "a/c" even though "a" is
// the smaller namespace.
func CompareByCreationTimestampAndObjectKey(a, b metav1.ObjectMeta) int {
	if c := a.CreationTimestamp.Time.Compare(b.CreationTimestamp.Time); c != 0 {
		return c
	}
	if c := cmp.Compare(a.Namespace, b.Namespace); c != 0 {
		return c
	}
	return cmp.Compare(a.Name, b.Name)
}
