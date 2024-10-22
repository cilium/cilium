// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package loader

import (
	"errors"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/testutils"
	"github.com/cilium/cilium/pkg/testutils/netns"
)

func TestMaybeUnloadObsoleteXDPPrograms(t *testing.T) {
	testutils.PrivilegedTest(t)

	ns := netns.NewNetNS(t)

	ns.Do(func() error {
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

		prog := mustXDPProgram(t, symbolFromHostNetdevXDP)
		basePath := testutils.TempBPFFS(t)
		veth0LinkPath := bpffsDeviceLinksDir(basePath, veth0)
		require.NoError(t, bpf.MkdirBPF(veth0LinkPath))
		veth1LinkPath := bpffsDeviceLinksDir(basePath, veth1)
		require.NoError(t, bpf.MkdirBPF(veth1LinkPath))
		// need to use symbolFromHostNetdevXDP as progName here as maybeUnloadObsoleteXDPPrograms explicitly uses that name.
		err = attachXDPProgram(veth0, prog, symbolFromHostNetdevXDP, veth0LinkPath, link.XDPDriverMode)
		require.NoError(t, err)

		err = attachXDPProgram(veth1, prog, symbolFromHostNetdevXDP, veth1LinkPath, link.XDPDriverMode)
		require.NoError(t, err)

		maybeUnloadObsoleteXDPPrograms(
			[]string{"veth0"}, option.XDPModeLinkDriver, basePath,
		)

		require.NoError(t, testutils.WaitUntil(func() bool {
			v1, err := h.LinkByName("veth1")
			require.NoError(t, err)
			if v1.Attrs().Xdp != nil {
				return v1.Attrs().Xdp.Attached == false
			}
			return true
		}, time.Second))

		v0, err := h.LinkByName("veth0")
		require.NoError(t, err)
		require.NotNil(t, v0.Attrs().Xdp)
		require.True(t, v0.Attrs().Xdp.Attached)

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

	ns := netns.NewNetNS(t)

	ns.Do(func() error {
		veth := &netlink.Veth{
			LinkAttrs: netlink.LinkAttrs{Name: "veth0"},
			PeerName:  "veth1",
		}
		err := netlink.LinkAdd(veth)
		require.NoError(t, err)

		prog := mustXDPProgram(t, "test")
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

	ns := netns.NewNetNS(t)

	ns.Do(func() error {
		veth := &netlink.Veth{
			LinkAttrs: netlink.LinkAttrs{Name: "veth0"},
			PeerName:  "veth1",
		}
		err := netlink.LinkAdd(veth)
		require.NoError(t, err)

		prog := mustXDPProgram(t, "test")
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

	ns := netns.NewNetNS(t)

	ns.Do(func() error {
		veth := &netlink.Veth{
			LinkAttrs: netlink.LinkAttrs{Name: "veth0"},
			PeerName:  "veth1",
		}
		err := netlink.LinkAdd(veth)
		require.NoError(t, err)

		prog := mustXDPProgram(t, "test")

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
		err = DetachXDP(veth.Attrs().Name, basePath, "test")
		require.NoError(t, err)

		err = netlink.LinkDel(veth)
		require.NoError(t, err)

		return nil
	})
}

// Detach an XDP program that was attached using netlink.
func TestDetachXDPWithPreviousAttach(t *testing.T) {
	testutils.PrivilegedTest(t)

	ns := netns.NewNetNS(t)
	ns.Do(func() error {
		var veth netlink.Link = &netlink.Veth{
			LinkAttrs: netlink.LinkAttrs{Name: "veth0"},
			PeerName:  "veth1",
		}
		err := netlink.LinkAdd(veth)
		require.NoError(t, err)

		prog := mustXDPProgram(t, "test")
		basePath := testutils.TempBPFFS(t)

		err = netlink.LinkSetXdpFdWithFlags(veth, prog.FD(), int(link.XDPGenericMode))
		require.NoError(t, err)
		require.True(t, getLink(t, veth).Attrs().Xdp.Attached)

		// Detach with the wrong name, leaving the program attached.
		err = DetachXDP(veth.Attrs().Name, basePath, "foo")
		require.NoError(t, err)
		require.True(t, getLink(t, veth).Attrs().Xdp.Attached)

		err = DetachXDP(veth.Attrs().Name, basePath, "test")
		require.NoError(t, err)
		require.False(t, getLink(t, veth).Attrs().Xdp.Attached)

		require.NoError(t, netlink.LinkDel(veth))

		return nil
	})
}

func getLink(tb testing.TB, link netlink.Link) netlink.Link {
	tb.Helper()

	req, err := netlink.LinkByIndex(link.Attrs().Index)
	require.NoError(tb, err)

	return req
}
