// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWriteZoneOutput(t *testing.T) {
	tests := []struct {
		name     string
		zone     string
		expected string
	}{
		{
			name:     "writes zone value",
			zone:     "zone-a",
			expected: "zone-a",
		},
		{
			name:     "writes empty zone value",
			zone:     "",
			expected: "",
		},
	}

	for _, tt := range tests {
		outputPath := filepath.Join(t.TempDir(), "service-zone")
		require.NoError(t, writeZoneOutput(outputPath, tt.zone))

		data, err := os.ReadFile(outputPath)
		require.NoError(t, err)
		assert.Equal(t, tt.expected, string(data))
	}
}
