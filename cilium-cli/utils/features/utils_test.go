// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package features

import (
	"fmt"
	"reflect"
	"sort"
	"testing"
)

func TestComputeFailureExceptions(t *testing.T) {
	defaultExceptions := []string{"reason0", "reason1"}
	tests := []struct {
		inputExceptions    []string
		expectedExceptions []string
	}{
		// Empty list of reasons.
		{
			inputExceptions:    []string{},
			expectedExceptions: []string{},
		},
		// Add a reason to default list.
		{
			inputExceptions:    []string{"+reason2"},
			expectedExceptions: []string{"reason0", "reason1", "reason2"},
		},
		// Remove a reason from default list.
		{
			inputExceptions:    []string{"-reason1"},
			expectedExceptions: []string{"reason0"},
		},
		// Add a reason then remove it.
		{
			inputExceptions:    []string{"+reason2", "-reason2"},
			expectedExceptions: []string{"reason0", "reason1"},
		},
		// Remove a reason then add it back.
		{
			inputExceptions:    []string{"-reason1", "+reason1"},
			expectedExceptions: []string{"reason0", "reason1"},
		},
	}

	for _, test := range tests {
		t.Run(fmt.Sprintf("InputExceptions: %v", test.inputExceptions), func(t *testing.T) {
			result := ComputeFailureExceptions(defaultExceptions, test.inputExceptions)

			// computeFailureExceptions doesn't guarantee the order of the
			// returned slice so we have to sort both slices.
			sort.Strings(result)
			if !reflect.DeepEqual(result, test.expectedExceptions) {
				t.Errorf("Expected exceptions to be %v, but got: %v", test.expectedExceptions, result)
			}
		})
	}
}
