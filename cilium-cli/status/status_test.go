// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package status

import (
	"encoding/json"
	"fmt"
	"testing"
)

func TestErrorCountMarshalJSON(t *testing.T) {
	tests := []struct {
		name     string
		input    *ErrorCount
		expected string
	}{
		{
			name: "No errors or warnings",
			input: &ErrorCount{
				Errors:   nil,
				Warnings: nil,
				Disabled: false,
			},
			expected: `{
 "Errors": [],
 "Warnings": [],
 "Disabled": false
}`,
		},
		{
			name: "With errors and warnings",
			input: &ErrorCount{
				Errors:   []error{fmt.Errorf("error 1"), fmt.Errorf("error 2")},
				Warnings: []error{fmt.Errorf("warning 1")},
				Disabled: false,
			},
			expected: `{
 "Errors": [
  "error 1",
  "error 2"
 ],
 "Warnings": [
  "warning 1"
 ],
 "Disabled": false
}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual, err := json.MarshalIndent(tt.input, "", " ")
			if err != nil {
				t.Fatalf("unexpected error during marshaling: %v", err)
			}

			if string(actual) != tt.expected {
				t.Errorf("expected %v, got %v", tt.expected, string(actual))
			}
		})
	}
}
