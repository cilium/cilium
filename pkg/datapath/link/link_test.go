// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package link

import (
	"testing"

	"github.com/cilium/cilium/pkg/testutils"

	. "github.com/cilium/checkmate"
	"github.com/vishvananda/netlink"
)

type LinkSuite struct{}

var _ = Suite(&LinkSuite{})

func (s *LinkSuite) SetUpSuite(c *C) {
	testutils.PrivilegedTest(c)
}

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
