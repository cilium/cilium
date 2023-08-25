// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build linux

package modules

import (
	"github.com/cilium/cilium/pkg/testutils"

	. "github.com/cilium/checkmate"
)

type ModulesPrivilegedTestSuite struct{}

var _ = Suite(&ModulesPrivilegedTestSuite{})

func (s *ModulesPrivilegedTestSuite) SetUpSuite(c *C) {
	testutils.PrivilegedTest(c)
}

func (s *ModulesPrivilegedTestSuite) TestFindOrLoadModules(c *C) {
	testCases := []struct {
		modulesToFind []string
		expectedErr   bool
	}{
		{
			modulesToFind: []string{"bridge"},
			expectedErr:   false,
		},
		{
			modulesToFind: []string{"foo", "bar"},
			expectedErr:   true,
		},
	}

	manager := &ModulesManager{}
	err := manager.Init()
	c.Assert(err, IsNil)

	for _, tc := range testCases {
		err = manager.FindOrLoadModules(tc.modulesToFind...)
		if tc.expectedErr {
			c.Assert(err, NotNil)
		} else {
			c.Assert(err, IsNil)
		}
	}
}
