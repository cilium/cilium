// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package loader

import (
	"errors"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"

	"github.com/cilium/cilium/pkg/bpf"

	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/testutils"
	"github.com/cilium/cilium/pkg/testutils/netns"
)

func TestPrivilegedMaybeUnloadObsoleteXDPPrograms(t *testing.T) {
	testutils.PrivilegedTest(t)
	logger := hivetest.Logger(t)

	basePath := testutils.TempBPFFS(t)
	prog := mustXDPProgram(t, symbolFromHostNetdevXDP)
	veth := &netlink.Veth{
		LinkAttrs: netlink.LinkAttrs{Name: "veth"},
		PeerName:  "peer",
	}

	ns := netns.NewNetNS(t)
	ns.Do(func() error {
		require.NoError(t, netlink.LinkAdd(veth))

		loLinkPath := bpffsDeviceLinksDir(basePath, lo)
		require.NoError(t, bpf.MkdirBPF(loLinkPath))
		vethLinkPath := bpffsDeviceLinksDir(basePath, veth)
		require.NoError(t, bpf.MkdirBPF(vethLinkPath))

		// need to use symbolFromHostNetdevXDP as progName here as maybeUnloadObsoleteXDPPrograms explicitly uses that name.
		require.NoError(t, attachXDPProgram(logger, lo, prog, symbolFromHostNetdevXDP, loLinkPath, link.XDPGenericMode))
		require.NoError(t, attachXDPProgram(logger, veth, prog, symbolFromHostNetdevXDP, vethLinkPath, link.XDPGenericMode))

		// Clean up all interfaces except lo.
		maybeUnloadObsoleteXDPPrograms(logger, []string{lo.Attrs().Name}, option.XDPModeLinkGeneric, basePath)

		// Wait for veth to be detached.
		require.NoError(t, testutils.WaitUntil(func() bool {
			obsolete := getLink(t, veth)
			if obsolete.Attrs().Xdp == nil {
				return false
			}

			return !obsolete.Attrs().Xdp.Attached
		}, time.Second))

		// Wait for lo to be attached.
		attached := getLink(t, lo)
		require.NotNil(t, attached.Attrs().Xdp)
		require.True(t, attached.Attrs().Xdp.Attached)

		return nil
	})
}

// Attach a program to a clean dummy device, no replacing necessary.
func TestPrivilegedAttachXDP(t *testing.T) {
	testutils.PrivilegedTest(t)
	logger := hivetest.Logger(t)

	ns := netns.NewNetNS(t)
	ns.Do(func() error {
		prog := mustXDPProgram(t, "test")
		basePath := testutils.TempBPFFS(t)

		require.NoError(t, attachXDPProgram(logger, lo, prog, "test", basePath, link.XDPGenericMode))

		return nil
	})
}

// Replace an existing program attached using netlink attach.
func TestPrivilegedAttachXDPWithPreviousAttach(t *testing.T) {
	testutils.PrivilegedTest(t)
	logger := hivetest.Logger(t)

	ns := netns.NewNetNS(t)
	ns.Do(func() error {
		prog := mustXDPProgram(t, "test")
		basePath := testutils.TempBPFFS(t)

		require.NoError(t, netlink.LinkSetXdpFdWithFlags(lo, prog.FD(), int(link.XDPGenericMode)))
		require.NoError(t, attachXDPProgram(logger, lo, prog, "test", basePath, link.XDPGenericMode))

		return nil
	})
}

// On kernels that support it, make sure an existing bpf_link can be updated.
func TestPrivilegedAttachXDPWithExistingLink(t *testing.T) {
	testutils.PrivilegedTest(t)
	logger := hivetest.Logger(t)

	ns := netns.NewNetNS(t)
	ns.Do(func() error {
		prog := mustXDPProgram(t, "test")

		// Probe XDP bpf_link support by manually attaching a Program and
		// immediately closing the link when it succeeds.
		l, err := link.AttachXDP(link.XDPOptions{
			Program:   prog,
			Interface: lo.Attrs().Index,
			Flags:     link.XDPGenericMode,
		})
		if errors.Is(err, ebpf.ErrNotSupported) {
			t.Skip("bpf_link is not supported")
		}
		require.NoError(t, err)
		require.NoError(t, l.Close())

		basePath := testutils.TempBPFFS(t)
		pinDir := bpffsDeviceLinksDir(basePath, lo)
		require.NoError(t, bpf.MkdirBPF(pinDir))

		// At this point, we know bpf_link is supported, so attachXDPProgram should
		// use it.
		require.NoError(t, attachXDPProgram(logger, lo, prog, "test", pinDir, link.XDPGenericMode))

		// Attach the same program again. This should update the existing link.
		require.NoError(t, attachXDPProgram(logger, lo, prog, "test", pinDir, link.XDPGenericMode))

		// Detach the program.
		require.NoError(t, DetachXDP(lo.Attrs().Name, basePath, "test"))

		return nil
	})
}

// Detach an XDP program that was attached using netlink.
func TestPrivilegedDetachXDPWithPreviousAttach(t *testing.T) {
	testutils.PrivilegedTest(t)

	ns := netns.NewNetNS(t)
	ns.Do(func() error {
		prog := mustXDPProgram(t, "test")
		basePath := testutils.TempBPFFS(t)

		require.NoError(t, netlink.LinkSetXdpFdWithFlags(lo, prog.FD(), int(link.XDPGenericMode)))
		require.True(t, getLink(t, lo).Attrs().Xdp.Attached)

		// Detach with the wrong name, leaving the program attached.
		require.NoError(t, DetachXDP(lo.Attrs().Name, basePath, "foo"))
		require.True(t, getLink(t, lo).Attrs().Xdp.Attached)

		require.NoError(t, DetachXDP(lo.Attrs().Name, basePath, "test"))
		require.False(t, getLink(t, lo).Attrs().Xdp.Attached)

		return nil
	})
}

func getLink(tb testing.TB, link netlink.Link) netlink.Link {
	tb.Helper()

	req, err := netlink.LinkByIndex(link.Attrs().Index)
	require.NoError(tb, err)

	return req
}
