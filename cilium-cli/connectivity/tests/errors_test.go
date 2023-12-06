// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package tests

import (
	"fmt"
	"strings"
	"testing"
)

func TestComputeExpectedDropReasons(t *testing.T) {
	defaultReasons := []string{"reason0", "reason1"}
	tests := []struct {
		inputReasons    []string
		expectedReasons []string
	}{
		// Empty list of reasons.
		{
			inputReasons:    []string{},
			expectedReasons: []string{},
		},
		// Add a reason to default list.
		{
			inputReasons:    []string{"+reason2"},
			expectedReasons: []string{"reason0", "reason1", "reason2"},
		},
		// Remove a reason from default list.
		{
			inputReasons:    []string{"-reason1"},
			expectedReasons: []string{"reason0"},
		},
		// Add a reason then remove it.
		{
			inputReasons:    []string{"+reason2", "-reason2"},
			expectedReasons: []string{"reason0", "reason1"},
		},
		// Remove a reason then add it back.
		{
			inputReasons:    []string{"-reason1", "+reason1"},
			expectedReasons: []string{"reason0", "reason1"},
		},
	}

	for _, test := range tests {
		t.Run(fmt.Sprintf("InputReasons: %v", test.inputReasons), func(t *testing.T) {
			result := computeExpectedDropReasons(defaultReasons, test.inputReasons)

			// computeExpectedDropReasons doesn't guarantee the order of the
			// emitted string so instead we check the length and that all
			// expected elements are listed.

			for _, expReason := range test.expectedReasons {
				if !strings.Contains(result, fmt.Sprintf("%q", expReason)) {
					t.Errorf("Expected filter to contain %q, but got: %v", expReason, result)
				}
			}

			// We know the expected length because all our test reasons are the same length.
			expectedLength := len(test.expectedReasons) * 9
			if len(test.expectedReasons) > 1 {
				expectedLength += (len(test.expectedReasons) - 1) * 2
			}
			if len(result) != expectedLength {
				t.Errorf("Expected filter of length %d, but got: %v", expectedLength, result)
			}
		})
	}
}
