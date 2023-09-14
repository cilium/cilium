// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package loader

import (
	"testing"

	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"

	"github.com/cilium/cilium/pkg/netns"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/testutils"
)

func TestMaybeUnloadObsoleteXDPPrograms(t *testing.T) {
	testutils.PrivilegedTest(t)

	netnsName := "test-maybe-unload-xdp"
	netns0, err := netns.ReplaceNetNSWithName(netnsName)
	require.NoError(t, err)
	require.NotNil(t, netns0)
	t.Cleanup(func() {
		netns0.Close()
		netns.RemoveNetNSWithName(netnsName)
	})

	netns0.Do(func(_ ns.NetNS) error {
		veth0 := &netlink.Veth{
			LinkAttrs: netlink.LinkAttrs{Name: "veth0"},
			PeerName:  "veth2",
		}
		err := netlink.LinkAdd(veth0)
		require.NoError(t, err)

		veth1 := &netlink.Veth{
			LinkAttrs: netlink.LinkAttrs{Name: "veth1"},
			PeerName:  "veth3",
		}
		err = netlink.LinkAdd(veth1)
		require.NoError(t, err)

		prog := mustXDPProgram(t)

		err = attachProgram(veth0, prog, "test", 0, xdpModeToFlag(option.XDPModeLinkGeneric))
		require.NoError(t, err)

		err = attachProgram(veth1, prog, "test", 0, xdpModeToFlag(option.XDPModeLinkGeneric))
		require.NoError(t, err)

		maybeUnloadObsoleteXDPPrograms([]string{"veth0"}, option.XDPModeLinkGeneric)

		v0, err := netlink.LinkByName("veth0")
		require.NoError(t, err)
		require.NotNil(t, v0.Attrs().Xdp)
		require.True(t, v0.Attrs().Xdp.Attached)

		v1, err := netlink.LinkByName("veth1")
		require.NoError(t, err)
		if v1.Attrs().Xdp != nil {
			require.False(t, v1.Attrs().Xdp.Attached)
		}

		err = netlink.LinkDel(veth0)
		require.NoError(t, err)

		err = netlink.LinkDel(veth1)
		require.NoError(t, err)

		return nil
	})
}
