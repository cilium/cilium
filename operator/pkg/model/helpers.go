// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package model

import "github.com/google/go-cmp/cmp"

func AddSource(sourceList []FullyQualifiedResource, source FullyQualifiedResource) []FullyQualifiedResource {
	for _, s := range sourceList {
		if cmp.Equal(s, source) {
			return sourceList
		}
	}
	return append(sourceList, source)
}
