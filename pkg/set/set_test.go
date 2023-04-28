// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package set

import (
	"testing"

	. "gopkg.in/check.v1"

	"github.com/cilium/cilium/pkg/checker"
)

// Hook up gocheck into the "go test" runner.
func Test(t *testing.T) {
	TestingT(t)
}

type SetTestSuite struct{}

var _ = Suite(&SetTestSuite{})

func (s *SetTestSuite) TestSliceSubsetOf(c *C) {
	testCases := []struct {
		sub          []string
		main         []string
		isSubset     bool
		expectedDiff []string
	}{
		{
			sub:          []string{"foo", "bar"},
			main:         []string{"foo", "bar", "baz"},
			isSubset:     true,
			expectedDiff: nil,
		},
		{
			sub:          []string{"foo", "bar"},
			main:         []string{"foo", "bar"},
			isSubset:     true,
			expectedDiff: nil,
		},
		{
			sub:          []string{"foo", "bar"},
			main:         []string{"foo", "baz"},
			isSubset:     false,
			expectedDiff: []string{"bar"},
		},
		{
			sub:          []string{"baz"},
			main:         []string{"foo", "bar"},
			isSubset:     false,
			expectedDiff: []string{"baz"},
		},
		{
			sub:          []string{"foo", "bar", "fizz"},
			main:         []string{"fizz", "buzz"},
			isSubset:     false,
			expectedDiff: []string{"foo", "bar"},
		},
		{
			sub:          []string{"foo", "foo", "bar"},
			main:         []string{"foo", "bar"},
			isSubset:     false,
			expectedDiff: nil,
		},
		{
			sub:          []string{"foo", "foo", "foo", "bar", "bar"},
			main:         []string{"foo", "foo", "bar"},
			isSubset:     false,
			expectedDiff: nil,
		},
		{
			sub:          []string{"foo"},
			main:         []string{},
			isSubset:     false,
			expectedDiff: []string{"foo"},
		},
		{
			sub:          []string{},
			main:         []string{"foo"},
			isSubset:     true,
			expectedDiff: nil,
		},
		{
			sub:          []string{},
			main:         []string{},
			isSubset:     true,
			expectedDiff: nil,
		},
		{
			sub:          nil,
			main:         nil,
			isSubset:     true,
			expectedDiff: nil,
		},
		{
			sub:          []string{"foo"},
			main:         nil,
			isSubset:     false,
			expectedDiff: []string{"foo"},
		},
		{
			sub:          nil,
			main:         []string{"foo"},
			isSubset:     true,
			expectedDiff: nil,
		},
		{
			sub:          []string{},
			main:         nil,
			isSubset:     true,
			expectedDiff: nil,
		},
	}
	for _, tc := range testCases {
		isSubset, diff := SliceSubsetOf(tc.sub, tc.main)
		c.Assert(isSubset, Equals, tc.isSubset)
		c.Assert(diff, checker.DeepEquals, tc.expectedDiff)
	}
}
