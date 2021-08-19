// SPDX-License-Identifier: Apache-2.0
// Copyright 2019 Authors of Cilium

//go:build linux && privileged_tests
// +build linux,privileged_tests

package modules

import (
	"testing"

	. "gopkg.in/check.v1"
)

// Hook up gocheck into the "go test" runner.
func Test(t *testing.T) {
	TestingT(t)
}

type ModulesPrivilegedTestSuite struct{}

var _ = Suite(&ModulesPrivilegedTestSuite{})

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
