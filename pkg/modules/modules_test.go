// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package modules

import (
	"testing"

	. "github.com/cilium/checkmate"

	"github.com/cilium/cilium/pkg/checker"
)

// Hook up gocheck into the "go test" runner.
func Test(t *testing.T) {
	TestingT(t)
}

type ModulesTestSuite struct{}

var _ = Suite(&ModulesTestSuite{})

func (s *ModulesTestSuite) TestInit(c *C) {
	var manager ModulesManager
	c.Assert(manager.Init(), IsNil)
}

func (s *ModulesTestSuite) TestFindModules(c *C) {
	manager := &ModulesManager{
		modulesList: []string{
			"ip6_tables",
			"ip6table_mangle",
			"ip6table_filter",
			"ip6table_security",
			"ip6table_raw",
			"ip6table_nat",
		},
	}
	testCases := []struct {
		modulesToFind []string
		isSubset      bool
		expectedDiff  []string
	}{
		{
			modulesToFind: []string{
				"ip6_tables",
				"ip6table_mangle",
				"ip6table_filter",
				"ip6table_security",
				"ip6table_raw",
				"ip6table_nat",
			},
			isSubset:     true,
			expectedDiff: nil,
		},
		{
			modulesToFind: []string{
				"ip6_tables",
				"ip6table_mangle",
				"ip6table_raw",
			},
			isSubset:     true,
			expectedDiff: nil,
		},
		{
			modulesToFind: []string{
				"ip6_tables",
				"ip6table_mangle",
				"ip6table_raw",
				"foo_module",
			},
			isSubset:     false,
			expectedDiff: []string{"foo_module"},
		},
		{
			modulesToFind: []string{
				"foo_module",
				"bar_module",
			},
			isSubset:     false,
			expectedDiff: []string{"foo_module", "bar_module"},
		},
	}
	for _, tc := range testCases {
		found, diff := manager.FindModules(tc.modulesToFind...)
		c.Assert(found, Equals, tc.isSubset)
		c.Assert(diff, checker.DeepEquals, tc.expectedDiff)
	}
}
