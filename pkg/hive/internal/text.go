// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package internal

import "strings"

// LeftPad pads all lines in string 's' with 'n' spaces.
func LeftPad(s string, n int) string {
	if s == "" {
		return ""
	}
	pad := strings.Repeat(" ", n)
	lines := strings.Split(s, "\n")
	for i := range lines {
		lines[i] = pad + lines[i]
	}
	return strings.Join(lines, "\n")
}
