// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package slices

import (
	"golang.org/x/exp/slices"
)

// DeleteFunc removes any elements from s for which del returns true,
// returning the modified slice.
// When DeleteFunc removes m elements, it might not modify the elements
// s[len(s)-m:len(s)]. If those elements contain pointers you might consider
// zeroing those elements so that objects they reference can be garbage
// collected.
func DeleteFunc[S ~[]E, E any](s S, del func(E) bool) S {
	i := slices.IndexFunc(s, del)
	if i == -1 {
		return s
	}
	// Don't start copying elements until we find one to delete.
	for j := i + 1; j < len(s); j++ {
		if v := s[j]; !del(v) {
			s[i] = v
			i++
		}
	}
	return s[:i]
}
