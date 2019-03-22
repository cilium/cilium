// Copyright 2019 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

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
