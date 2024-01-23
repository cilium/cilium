// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package comparator

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMapStringEqualsIgnoreKeys(t *testing.T) {
	tests := []struct {
		name         string
		m1           map[string]string
		m2           map[string]string
		keysToIgnore []string
		want         bool
	}{
		{
			name: "test-1",
			m1:   nil,
			m2:   nil,
			want: true,
		},
		{
			m1: map[string]string{
				"foo": "bar",
			},
			m2: map[string]string{
				"foo": "bar",
			},
			want: true,
		},
		{
			name: "test-2",
			m1:   map[string]string{},
			m2:   map[string]string{},
			want: true,
		},
		{
			name: "test-3",
			m1: map[string]string{
				"fo": "bar",
			},
			m2: map[string]string{
				"foo": "bar",
			},
			want: false,
		},
		{
			name: "test-4",
			m1:   nil,
			m2: map[string]string{
				"foo": "bar",
			},
			want: false,
		},
		{
			name: "test-5",
			m1: map[string]string{
				"foo": "bar",
			},
			m2:   nil,
			want: false,
		},
		{
			name: "test-6",
			m1: map[string]string{
				"foo": "bar",
			},
			m2:   nil,
			want: false,
		},
		{
			name: "test-7",
			m1: map[string]string{
				"foo": "bar",
			},
			m2:           nil,
			keysToIgnore: []string{"foo"},
			// Although we are ignoring "foo", m2 is nil.
			want: false,
		},
		{
			name: "test-8",
			m1: map[string]string{
				"foo": "bar",
			},
			m2:           map[string]string{},
			keysToIgnore: []string{"foo"},
			want:         true,
		},
		{
			name: "test-9",
			m1:   map[string]string{},
			m2: map[string]string{
				"foo": "bar",
			},
			keysToIgnore: []string{"foo"},
			want:         true,
		},
		{
			name:         "test-10",
			m1:           map[string]string{},
			m2:           map[string]string{},
			keysToIgnore: []string{"foo"},
			want:         true,
		},
		{
			name: "test-10",
			m1:   nil,
			m2: map[string]string{
				"foo": "bar",
			},
			keysToIgnore: []string{"foo"},
			want:         false,
		},
	}
	for _, tt := range tests {
		assert.Equal(t, tt.want, MapStringEqualsIgnoreKeys(tt.m1, tt.m2, tt.keysToIgnore), "%s", tt.name)
	}
}
