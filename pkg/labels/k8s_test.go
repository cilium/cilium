// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package labels

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestK8sLabelArrayLookup(t *testing.T) {
	lbls := K8sLabelArray{
		NewLabel("env", "devel", LabelSourceAny),
		NewLabel("user", "bob", LabelSourceContainer),
	}
	var hasTests = []struct {
		input    string // input
		result   string // result of the lookup
		expected bool   // expected result
	}{
		{"", "", false},
		{"any", "", false},
		{"env", "devel", true},
		{"container.env", "", false},
		{"container:env", "", false},
		{"any:env", "", false},
		{"any.env", "devel", true},
		{"any:user", "", false},
		{"any.user", "bob", true},
		{"user", "bob", true},
		{"container.user", "bob", true},
		{"container:user", "", false},
		{"container:bob", "", false},
	}
	for _, tt := range hasTests {
		t.Logf("Lookup %s", tt.input)
		lookup, exist := lbls.Lookup(tt.input)

		require.Equal(t, tt.result, lookup)
		require.Equal(t, tt.expected, exist)
	}
}
