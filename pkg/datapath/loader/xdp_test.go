// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package loader

import (
	"errors"
	"testing"
	"time"

	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"

	"github.com/cilium/cilium/pkg/bpf"
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
		// create netlink handle in the test netns to ensure subsequent netlink
		// calls request data from the correct netns, even if called in a separate
		// goroutine (require.Eventually)
		h, err := netlink.NewHandle()
		require.NoError(t, err)

		veth0 := &netlink.Veth{
			LinkAttrs: netlink.LinkAttrs{Name: "veth0"},
			PeerName:  "veth2",
		}
		err = h.LinkAdd(veth0)
		require.NoError(t, err)

		veth1 := &netlink.Veth{
			LinkAttrs: netlink.LinkAttrs{Name: "veth1"},
			PeerName:  "veth3",
		}
		err = h.LinkAdd(veth1)
		require.NoError(t, err)

		prog := mustXDPProgram(t)
		basePath := testutils.TempBPFFS(t)

		// need to use symbolFromHostNetdevXDP as progName here as maybeUnloadObsoleteXDPPrograms explicitly uses that name.
		err = attachXDPProgram(veth0, prog, symbolFromHostNetdevXDP, basePath, link.XDPGenericMode)
		require.NoError(t, err)

		err = attachXDPProgram(veth1, prog, symbolFromHostNetdevXDP, basePath, link.XDPGenericMode)
		require.NoError(t, err)

		maybeUnloadObsoleteXDPPrograms([]string{"veth0"}, option.XDPModeLinkGeneric, basePath)

		v0, err := h.LinkByName("veth0")
		require.NoError(t, err)
		require.NotNil(t, v0.Attrs().Xdp)
		require.True(t, v0.Attrs().Xdp.Attached)

		require.Eventually(t, func() bool {
			v1, err := h.LinkByName("veth1")
			require.NoError(t, err)
			if v1.Attrs().Xdp != nil {
				return v1.Attrs().Xdp.Attached == false
			}
			return true
		}, 150*time.Millisecond, 15*time.Millisecond)

		err = netlink.LinkDel(veth0)
		require.NoError(t, err)

		err = netlink.LinkDel(veth1)
		require.NoError(t, err)

		return nil
	})
}

// Attach a program to a clean dummy device, no replacing necessary.
func TestAttachXDP(t *testing.T) {
	testutils.PrivilegedTest(t)

	netnsName := "test-attach-xdp"
	netns0, err := netns.ReplaceNetNSWithName(netnsName)
	require.NoError(t, err)
	require.NotNil(t, netns0)
	t.Cleanup(func() {
		netns0.Close()
		netns.RemoveNetNSWithName(netnsName)
	})

	netns0.Do(func(_ ns.NetNS) error {
		veth := &netlink.Veth{
			LinkAttrs: netlink.LinkAttrs{Name: "veth0"},
			PeerName:  "veth1",
		}
		err := netlink.LinkAdd(veth)
		require.NoError(t, err)

		prog := mustXDPProgram(t)
		basePath := testutils.TempBPFFS(t)

		err = attachXDPProgram(veth, prog, "test", basePath, link.XDPGenericMode)
		require.NoError(t, err)

		err = netlink.LinkDel(veth)
		require.NoError(t, err)

		return nil
	})
}

// Replace an existing program attached using netlink attach.
func TestAttachXDPWithPreviousAttach(t *testing.T) {
	testutils.PrivilegedTest(t)

	netnsName := "test-attach-xdp-previous"
	netns0, err := netns.ReplaceNetNSWithName(netnsName)
	require.NoError(t, err)
	require.NotNil(t, netns0)
	t.Cleanup(func() {
		netns0.Close()
		netns.RemoveNetNSWithName(netnsName)
	})

	netns0.Do(func(_ ns.NetNS) error {
		veth := &netlink.Veth{
			LinkAttrs: netlink.LinkAttrs{Name: "veth0"},
			PeerName:  "veth1",
		}
		err := netlink.LinkAdd(veth)
		require.NoError(t, err)

		prog := mustXDPProgram(t)
		basePath := testutils.TempBPFFS(t)

		err = netlink.LinkSetXdpFdWithFlags(veth, prog.FD(), int(link.XDPGenericMode))
		require.NoError(t, err)

		err = attachXDPProgram(veth, prog, "test", basePath, link.XDPGenericMode)
		require.NoError(t, err)

		err = netlink.LinkDel(veth)
		require.NoError(t, err)

		return nil
	})
}

// On kernels that support it, make sure an existing bpf_link can be updated.
func TestAttachXDPWithExistingLink(t *testing.T) {
	testutils.PrivilegedTest(t)

	netnsName := "test-attach-xdp-existing"
	netns0, err := netns.ReplaceNetNSWithName(netnsName)
	require.NoError(t, err)
	require.NotNil(t, netns0)
	t.Cleanup(func() {
		netns0.Close()
		netns.RemoveNetNSWithName(netnsName)
	})

	netns0.Do(func(_ ns.NetNS) error {
		veth := &netlink.Veth{
			LinkAttrs: netlink.LinkAttrs{Name: "veth0"},
			PeerName:  "veth1",
		}
		err := netlink.LinkAdd(veth)
		require.NoError(t, err)

		prog := mustXDPProgram(t)

		// Probe XDP bpf_link support by manually attaching a Program and
		// immediately closing the link when it succeeds.
		l, err := link.AttachXDP(link.XDPOptions{
			Program:   prog,
			Interface: veth.Attrs().Index,
			Flags:     link.XDPGenericMode,
		})
		if errors.Is(err, ebpf.ErrNotSupported) {
			t.Skip("bpf_link is not supported")
		}
		require.NoError(t, err)
		require.NoError(t, l.Close())

		basePath := testutils.TempBPFFS(t)
		pinDir := bpffsDeviceLinksDir(basePath, veth)
		require.NoError(t, bpf.MkdirBPF(pinDir))

		// At this point, we know bpf_link is supported, so attachXDPProgram should
		// use it.
		err = attachXDPProgram(veth, prog, "test", pinDir, link.XDPGenericMode)
		require.NoError(t, err)

		// Attach the same program again. This should update the existing link.
		err = attachXDPProgram(veth, prog, "test", pinDir, link.XDPGenericMode)
		require.NoError(t, err)

		// Detach the program.
		err = DetachXDP(veth, basePath, "test")
		require.NoError(t, err)

		err = netlink.LinkDel(veth)
		require.NoError(t, err)

		return nil
	})
}

// Detach an XDP program that was attached using netlink.
func TestDetachXDPWithPreviousAttach(t *testing.T) {
	testutils.PrivilegedTest(t)

	netnsName := "test-detach-xdp-previous"
	netns0, err := netns.ReplaceNetNSWithName(netnsName)
	require.NoError(t, err)
	require.NotNil(t, netns0)
	t.Cleanup(func() {
		netns0.Close()
		netns.RemoveNetNSWithName(netnsName)
	})

	netns0.Do(func(_ ns.NetNS) error {
		veth := &netlink.Veth{
			LinkAttrs: netlink.LinkAttrs{Name: "veth0"},
			PeerName:  "veth1",
		}
		err := netlink.LinkAdd(veth)
		require.NoError(t, err)

		prog := mustXDPProgram(t)
		basePath := testutils.TempBPFFS(t)

		err = netlink.LinkSetXdpFdWithFlags(veth, prog.FD(), int(link.XDPGenericMode))
		require.NoError(t, err)

		err = DetachXDP(veth, basePath, "test")
		require.NoError(t, err)

		err = netlink.LinkDel(veth)
		require.NoError(t, err)

		return nil
	})
}
