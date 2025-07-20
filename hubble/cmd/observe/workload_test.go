// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package observe

import (
	"testing"

	"github.com/stretchr/testify/assert"

	flowpb "github.com/cilium/cilium/api/v1/flow"
)

func TestParseWorkload(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected *flowpb.Workload
	}{
		{
			name:     "empty",
			expected: &flowpb.Workload{},
		},
		{
			name:     "kind and name",
			input:    "Deployment/foo-deploy",
			expected: &flowpb.Workload{Kind: "Deployment", Name: "foo-deploy"},
		},
		{
			name:     "kind only",
			input:    "Deployment/",
			expected: &flowpb.Workload{Kind: "Deployment"},
		},
		{
			name:     "name only", // no trailing /
			input:    "foo-deploy",
			expected: &flowpb.Workload{Name: "foo-deploy"},
		},
		{
			name:  "multiple slashes",
			input: "Deployment/foo/bar/",
			// this isn't a valid resource name, but we don't validate that extensively
			expected: &flowpb.Workload{Kind: "Deployment", Name: "foo/bar/"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseWorkload(tt.input)
			assert.Equal(t, tt.expected, got)
		})
	}
}
