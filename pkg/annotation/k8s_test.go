// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package annotation

import (
	"testing"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
)

func TestGet(t *testing.T) {
	var (
		key     = "key"
		aliases = []string{"key-alt-1", "key-alt-2"}
		obj     = corev1.Service{}
	)

	tests := []struct {
		name        string
		annotations map[string]string
		wantValue   string
		wantOK      bool
	}{
		{
			"the searched annotation is not present",
			map[string]string{"other": "other"},
			"", false,
		},
		{
			"the searched annotation is present (preferred key)",
			map[string]string{"key": "value", "other": "other"},
			"value", true,
		},
		{
			"the searched annotation is present (alias)",
			map[string]string{"key-alt-1": "value-alt-1", "other": "other"},
			"value-alt-1", true,
		},
		{
			"the searched annotation is present (both preferred and alias keys)",
			map[string]string{"key": "value", "key-alt-1": "value-alt-1", "other": "other"},
			"value", true,
		},
		{
			"the searched annotation is present (both alias keys)",
			map[string]string{"key-alt-1": "value-alt-1", "key-alt-2": "value-alt-2", "other": "other"},
			"value-alt-1", true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			obj.ObjectMeta.Annotations = tt.annotations
			value, ok := Get(&obj, key, aliases...)
			require.Equal(t, tt.wantValue, value)
			require.Equal(t, tt.wantOK, ok)
		})
	}
}
