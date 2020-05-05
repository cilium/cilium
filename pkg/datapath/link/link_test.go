// Copyright 2020 Authors of Cilium
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

// +build privileged_tests

package link

import (
	"testing"

	"github.com/vishvananda/netlink"
	. "gopkg.in/check.v1"
)

type LinkSuite struct{}

var _ = Suite(&LinkSuite{})

func Test(t *testing.T) {
	TestingT(t)
}

func (s *LinkSuite) TestDeleteByName(c *C) {
	testCases := []struct {
		name        string
		create      bool
		expectError bool
	}{
		{
			"foo",
			true,
			false,
		},
		{
			"bar",
			false,
			true,
		},
	}
	var err error

	for _, tc := range testCases {
		if tc.create {
			err = netlink.LinkAdd(&netlink.Dummy{
				LinkAttrs: netlink.LinkAttrs{
					Name: tc.name,
				},
			})
			c.Assert(err, IsNil)
		}

		err = DeleteByName(tc.name)
		if tc.expectError {
			c.Assert(err, NotNil)
		} else {
			c.Assert(err, IsNil)
		}
	}
}

func (s *LinkSuite) TestRename(c *C) {
	testCases := []struct {
		curName     string
		newName     string
		create      bool
		expectError bool
	}{
		{
			"abc",
			"xyz",
			true,
			false,
		},
		{
			"fizz",
			"buzz",
			false,
			true,
		},
	}
	var err error

	for _, tc := range testCases {
		if tc.create {
			err = netlink.LinkAdd(&netlink.Dummy{
				LinkAttrs: netlink.LinkAttrs{
					Name: tc.curName,
				},
			})
			c.Assert(err, IsNil)
		}

		err = Rename(tc.curName, tc.newName)
		if tc.expectError {
			c.Assert(err, NotNil)
		} else {
			c.Assert(err, IsNil)
		}

		DeleteByName(tc.newName)
	}
}
