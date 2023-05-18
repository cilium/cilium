// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package comparator

import (
	"testing"

	. "github.com/cilium/checkmate"
)

// Hook up gocheck into the "go test" runner.
func Test(t *testing.T) {
	TestingT(t)
}

type ComparatorSuite struct{}

var _ = Suite(&ComparatorSuite{})

func (s *ComparatorSuite) TestMapStringEquals(c *C) {
	tests := []struct {
		m1   map[string]string
		m2   map[string]string
		want bool
	}{
		{
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
			m1:   map[string]string{},
			m2:   map[string]string{},
			want: true,
		},
		{
			m1: map[string]string{
				"fo": "bar",
			},
			m2: map[string]string{
				"foo": "bar",
			},
			want: false,
		},
		{
			m1: nil,
			m2: map[string]string{
				"foo": "bar",
			},
			want: false,
		},
		{
			m1: map[string]string{
				"foo": "bar",
			},
			m2:   nil,
			want: false,
		},
		{
			m1: map[string]string{
				"foo": "bar",
			},
			m2:   nil,
			want: false,
		},
	}
	for _, tt := range tests {
		c.Assert(MapStringEquals(tt.m1, tt.m2), Equals, tt.want)
	}
}

func (s *ComparatorSuite) TestMapBoolEquals(c *C) {
	tests := []struct {
		m1   map[string]bool
		m2   map[string]bool
		want bool
	}{
		{
			m1:   nil,
			m2:   nil,
			want: true,
		},
		{
			m1: map[string]bool{
				"foo": true,
			},
			m2: map[string]bool{
				"foo": true,
			},
			want: true,
		},
		{
			m1:   map[string]bool{},
			m2:   map[string]bool{},
			want: true,
		},
		{
			m1: map[string]bool{
				"fo": true,
			},
			m2: map[string]bool{
				"foo": true,
			},
			want: false,
		},
		{
			m1: nil,
			m2: map[string]bool{
				"foo": true,
			},
			want: false,
		},
		{
			m1: map[string]bool{
				"foo": true,
			},
			m2:   nil,
			want: false,
		},
		{
			m1: map[string]bool{
				"foo": true,
			},
			m2:   nil,
			want: false,
		},
	}
	for _, tt := range tests {
		c.Assert(MapBoolEquals(tt.m1, tt.m2), Equals, tt.want)
	}
}

func (s *ComparatorSuite) TestMapStringEqualsIgnoreKeys(c *C) {
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
		c.Assert(MapStringEqualsIgnoreKeys(tt.m1, tt.m2, tt.keysToIgnore), Equals, tt.want, Commentf("%s", tt.name))
	}
}
