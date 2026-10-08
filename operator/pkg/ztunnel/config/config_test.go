// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package config

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSpiffeIDPathFunc(t *testing.T) {
	tests := []struct {
		name           string
		namespacedname string
		expected       string
	}{
		{
			name:           "valid namespace/serviceaccount",
			namespacedname: "default/my-service",
			expected:       "/ns/default/sa/my-service",
		},
		{
			name:           "kube-system namespace",
			namespacedname: "kube-system/coredns",
			expected:       "/ns/kube-system/sa/coredns",
		},
		{
			name:           "invalid format - no slash",
			namespacedname: "invalid",
			expected:       "",
		},
		{
			name:           "invalid format - too many parts",
			namespacedname: "a/b/c",
			expected:       "",
		},
		{
			name:           "empty string",
			namespacedname: "",
			expected:       "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := SpiffeIDPathFunc(tt.namespacedname)
			require.Equal(t, tt.expected, result)
		})
	}
}

func TestSpiffeIDSelectorsFunc(t *testing.T) {
	tests := []struct {
		name           string
		namespacedname string
		expectedLen    int
		expectedNs     string
		expectedSa     string
	}{
		{
			name:           "valid namespace/serviceaccount",
			namespacedname: "default/my-service",
			expectedLen:    2,
			expectedNs:     "ns:default",
			expectedSa:     "sa:my-service",
		},
		{
			name:           "kube-system namespace",
			namespacedname: "kube-system/coredns",
			expectedLen:    2,
			expectedNs:     "ns:kube-system",
			expectedSa:     "sa:coredns",
		},
		{
			name:           "invalid format - no slash",
			namespacedname: "invalid",
			expectedLen:    0,
		},
		{
			name:           "invalid format - too many parts",
			namespacedname: "a/b/c",
			expectedLen:    0,
		},
		{
			name:           "empty string",
			namespacedname: "",
			expectedLen:    0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := SpiffeIDSelectorsFunc(tt.namespacedname)
			require.Len(t, result, tt.expectedLen)

			if tt.expectedLen == 2 {
				require.Equal(t, "k8s", result[0].Type)
				require.Equal(t, tt.expectedNs, result[0].Value)
				require.Equal(t, "k8s", result[1].Type)
				require.Equal(t, tt.expectedSa, result[1].Value)
			}
		})
	}
}
