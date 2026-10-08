// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package time

import (
	"testing"
	"time"
)

func TestFromString(t *testing.T) {
	restore := hijackNow()
	defer restore()

	tests := []struct {
		input    string
		expected string
	}{
		{
			input:    "10s",
			expected: "2019-07-01T13:59:50Z",
		},
		{
			input:    "5m",
			expected: "2019-07-01T13:55:00Z",
		},
		{
			input:    "20h",
			expected: "2019-06-30T18:00:00Z",
		},
		{
			input:    "2019-06-30T18:00:00Z",
			expected: "2019-06-30T18:00:00Z",
		},
		{
			input:    "2019-06-30",
			expected: "2019-06-30T00:00:00Z",
		},
		{
			input:    "2019-06-30T18Z",
			expected: "2019-06-30T18:00:00Z",
		},
		{
			input:    "2019-06-30T18:45Z",
			expected: "2019-06-30T18:45:00Z",
		},
		{
			input:    "2019-06-30T18+02:00",
			expected: "2019-06-30T16:00:00Z",
		},
		{
			input:    "2019-06-30T18:45+02:00",
			expected: "2019-06-30T16:45:00Z",
		},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got, err := FromString(tt.input)
			if err != nil {
				t.Errorf("failed to parse %s", tt.input)
			}

			expected, err := FromString(tt.expected)
			if err != nil {
				t.Errorf("failed to parse %s", tt.expected)
			}

			if !got.Equal(expected) {
				t.Errorf("%s should equal %s", got, expected)
			}
		})
	}
}

func hijackNow() func() {
	// assume now is July 1st, 2019, 14:00 exactly
	Now = func() time.Time {
		t, err := time.Parse(time.RFC3339, "2019-07-01T14:00:00Z")
		if err != nil {
			panic(err)
		}
		return t
	}
	return func() {
		Now = time.Now
	}
}
