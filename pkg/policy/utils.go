// SPDX-License-Identifier: Apache-2.0
// Copyright 2016-2017 Authors of Cilium

package policy

import "github.com/cilium/cilium/pkg/labels"

// JoinPath returns a joined path from a and b.
func JoinPath(a, b string) string {
	return a + labels.PathDelimiter + b
}
