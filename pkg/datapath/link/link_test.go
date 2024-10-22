// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package link

import (
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"

	"github.com/cilium/cilium/pkg/testutils"
)

func setup(tb testing.TB) {
	testutils.PrivilegedTest(tb)
}

func TestDeleteByName(t *testing.T) {
	setup(t)

	testCases := []struct {
		name   string
		create bool
	}{
		{"foo", true},
		{"bar", false},
	}
	var err error

	for _, tc := range testCases {
		if tc.create {
			err = netlink.LinkAdd(&netlink.Dummy{
				LinkAttrs: netlink.LinkAttrs{
					Name: tc.name,
				},
			})
			require.Nil(t, err)
		}

		require.Nil(t, DeleteByName(tc.name))
	}
}

func TestRename(t *testing.T) {
	setup(t)

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
			require.Nil(t, err)
		}

		err = Rename(tc.curName, tc.newName)
		if tc.expectError {
			require.Error(t, err)
		} else {
			require.Nil(t, err)
		}

		DeleteByName(tc.newName)
	}
}
