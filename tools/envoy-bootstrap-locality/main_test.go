// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package main

import (
	"os"
	"path/filepath"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

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

func TestLookupNodeZone(t *testing.T) {
	tests := []struct {
		name        string
		labels      map[string]string
		expected    string
		expectedErr string
	}{
		{
			name: "returns zone label",
			labels: map[string]string{
				nodeZoneLabel: "zone-a",
			},
			expected: "zone-a",
		},
		{
			name:        "fails when zone label is missing",
			labels:      map[string]string{},
			expectedErr: nodeZoneLabel,
		},
	}

	for _, tt := range tests {
		client := fake.NewSimpleClientset(&corev1.Node{
			ObjectMeta: metav1.ObjectMeta{
				Name:   "node-a",
				Labels: tt.labels,
			},
		})

		zone, err := lookupNodeZone(t.Context(), client, "node-a")
		if tt.expectedErr != "" {
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.expectedErr)
			assert.Empty(t, zone)
			continue
		}

		require.NoError(t, err)
		assert.Equal(t, tt.expected, zone)
	}
}
