// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package envoy

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSanitizeServerNamePattern(t *testing.T) {
	for in, expected := range map[string]string{
		"cilium.io":                  "cilium.io",
		"cilium.io.":                 "cilium.io",
		"test.cilium.io.":            "test.cilium.io",
		"*.cilium.io":                "*.cilium.io",
		"**.cilium.io":               "**.cilium.io",
		"***.cilium.io":              "**.cilium.io",
		"***.cilium*.io.":            "**.cilium*.io",
		"***.*cilium*.io":            "**.*cilium*.io",
		"***.test.**.cilium.io":      "**.test.*.cilium.io",
		"***.test-*.****.cilium.io.": "**.test-*.*.cilium.io",
		"*":                          "*",
		"**":                         "*",
		"****":                       "*",
	} {
		require.Equal(t, expected, sanitizeServerNamePattern(in))
	}
}
