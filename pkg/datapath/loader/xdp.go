// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package loader

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/vishvananda/netlink"

	"golang.org/x/sys/unix"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/mac"
	"github.com/cilium/cilium/pkg/option"
)

func xdpModeToFlag(xdpMode string) link.XDPAttachFlags {
	switch xdpMode {
	case option.XDPModeNative, option.XDPModeLinkDriver:
		return link.XDPDriverMode
	case option.XDPModeGeneric, option.XDPModeLinkGeneric:
		return link.XDPGenericMode
	}
	return 0
}

// maybeUnloadObsoleteXDPPrograms removes bpf_xdp.o from previously used
// devices.
//
// bpffsBase is typically set to /sys/fs/bpf/cilium, but can be a temp directory
// during tests.
func maybeUnloadObsoleteXDPPrograms(xdpDevs []string, xdpMode, bpffsBase string) {
	links, err := netlink.LinkList()
	if err != nil {
		log.WithError(err).Warn("Failed to list links for XDP unload")
	}

	for _, link := range links {
		linkxdp := link.Attrs().Xdp
		if linkxdp == nil || !linkxdp.Attached {
			// No XDP program is attached
			continue
		}
		if strings.Contains(link.Attrs().Name, "cilium") {
			// Ignore devices created by cilium-agent
			continue
		}

		used := false
		for _, xdpDev := range xdpDevs {
			if link.Attrs().Name == xdpDev &&
				linkxdp.AttachMode == uint32(xdpModeToFlag(xdpMode)) {
				// XDP mode matches; don't unload, otherwise we might introduce
				// intermittent connectivity problems
				used = true
				break
			}
		}
		if !used {
			if err := DetachXDP(link, bpffsBase, symbolFromHostNetdevXDP); err != nil {
				log.WithError(err).Warn("Failed to detach obsolete XDP program")
			}
		}
	}
}

// maybeRemoveXDPLinks removes bpf_links for XDP programs.
//
// This is needed for the downgrade path from newer Cilium versions that attach
// XDP using bpf_link. If this is not supported by an old version of Cilium, the
// bpf_link needs to be removed by deleting its pin from bpffs. Then, the old
// version will be able to attach XDP programs using the legacy netlink again.
func maybeRemoveXDPLinks() {
	links, err := netlink.LinkList()
	if err != nil {
		log.WithError(err).Warn("Failed to list links for XDP link removal")
	}

	for _, link := range links {
		bpfLinkPath := filepath.Join(bpffsDeviceLinksDir(bpf.CiliumPath(), link), symbolFromHostNetdevXDP)
		if err := os.Remove(bpfLinkPath); err != nil && !errors.Is(err, os.ErrNotExist) {
			log.WithError(err).Errorf("Failed to remove link %s", bpfLinkPath)
		}
	}
}

// xdpCompileArgs derives compile arguments for bpf_xdp.c.
func xdpCompileArgs(xdpDev string, extraCArgs []string) ([]string, error) {
	link, err := netlink.LinkByName(xdpDev)
	if err != nil {
		return nil, err
	}

	args := []string{
		fmt.Sprintf("-DSECLABEL=%d", identity.ReservedIdentityWorld),
		fmt.Sprintf("-DNODE_MAC={.addr=%s}", mac.CArrayString(link.Attrs().HardwareAddr)),
		"-DCALLS_MAP=cilium_calls_xdp",
	}
	args = append(args, extraCArgs...)
	if option.Config.EnableNodePort {
		args = append(args, []string{
			fmt.Sprintf("-DTHIS_MTU=%d", link.Attrs().MTU),
			fmt.Sprintf("-DNATIVE_DEV_IFINDEX=%d", link.Attrs().Index),
			"-DDISABLE_LOOPBACK_LB",
		}...)
	}
	if option.Config.IsDualStack() {
		args = append(args, fmt.Sprintf("-DSECLABEL_IPV4=%d", identity.ReservedIdentityWorldIPv4))
		args = append(args, fmt.Sprintf("-DSECLABEL_IPV6=%d", identity.ReservedIdentityWorldIPv6))
	} else {
		args = append(args, fmt.Sprintf("-DSECLABEL_IPV4=%d", identity.ReservedIdentityWorld))
		args = append(args, fmt.Sprintf("-DSECLABEL_IPV6=%d", identity.ReservedIdentityWorld))
	}

	return args, nil
}

// compileAndLoadXDPProg compiles bpf_xdp.c for the given XDP device and loads it.
func compileAndLoadXDPProg(ctx context.Context, xdpDev, xdpMode string, extraCArgs []string) error {
	args, err := xdpCompileArgs(xdpDev, extraCArgs)
	if err != nil {
		return fmt.Errorf("failed to derive XDP compile extra args: %w", err)
	}

	dirs := &directoryInfo{
		Library: option.Config.BpfDir,
		Runtime: option.Config.StateDir,
		Output:  option.Config.StateDir,
		State:   option.Config.StateDir,
	}
	prog := &progInfo{
		Source:     xdpProg,
		Output:     xdpObj,
		OutputType: outputObject,
		Options:    args,
	}

	if err := compile(ctx, prog, dirs); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}

	objPath := path.Join(dirs.Output, prog.Output)
	progs := []progDefinition{{progName: symbolFromHostNetdevXDP, direction: ""}}
	finalize, err := replaceDatapath(ctx, xdpDev, objPath, progs, xdpMode)
	if err != nil {
		return err
	}
	finalize()

	return err
}

// attachXDPProgram attaches prog with the given progName to link.
//
// bpffsDir should exist and point to the links/ subdirectory in the per-device
// bpffs directory.
func attachXDPProgram(iface netlink.Link, prog *ebpf.Program, progName, bpffsDir string, flags link.XDPAttachFlags) error {
	// Attempt to open and update an existing link.
	pin := filepath.Join(bpffsDir, progName)
	err := bpf.UpdateLink(pin, prog)
	switch {
	// Update successful, nothing left to do.
	case err == nil:
		log.Infof("Updated link %s for program %s", pin, progName)

		return nil

	// Link exists, but is defunct, and needs to be recreated. The program
	// no longer gets triggered at this point and the link needs to be removed
	// to proceed.
	case errors.Is(err, unix.ENOLINK):
		if err := os.Remove(pin); err != nil {
			return fmt.Errorf("unpinning defunct link %s: %w", pin, err)
		}

		log.Infof("Unpinned defunct link %s for program %s", pin, progName)

	// No existing link found, continue trying to create one.
	case errors.Is(err, os.ErrNotExist):
		log.Infof("No existing link found at %s for program %s", pin, progName)

	default:
		return fmt.Errorf("updating link %s for program %s: %w", pin, progName, err)
	}

	// Create a new link. This will only succeed on nodes that support bpf_link
	// and don't have any XDP programs attached through netlink.
	l, err := link.AttachXDP(link.XDPOptions{
		Program:   prog,
		Interface: iface.Attrs().Index,
		Flags:     flags,
	})
	if err == nil {
		defer func() {
			// The program was successfully attached using bpf_link. Closing a link
			// does not detach the program if the link is pinned.
			if err := l.Close(); err != nil {
				log.Warnf("Failed to close bpf_link for program %s", progName)
			}
		}()

		if err := l.Pin(pin); err != nil {
			return fmt.Errorf("pinning link at %s for program %s : %w", pin, progName, err)
		}

		// Successfully created and pinned bpf_link.
		log.Infof("Program %s attached using bpf_link", progName)

		return nil
	}

	// Kernels before 5.7 don't support bpf_link. In that case link.AttachXDP
	// returns ErrNotSupported.
	//
	// If the kernel supports bpf_link, but an older version of Cilium attached a
	// XDP program, link.AttachXDP will return EBUSY.
	if !errors.Is(err, unix.EBUSY) && !errors.Is(err, link.ErrNotSupported) {
		// Unrecoverable error from AttachRawLink.
		return fmt.Errorf("attaching program %s using bpf_link: %w", progName, err)
	}

	log.Debugf("Performing netlink attach for program %s", progName)

	// Omitting XDP_FLAGS_UPDATE_IF_NOEXIST equals running 'ip' with -force,
	// and will clobber any existing XDP attachment to the interface, including
	// bpf_link attachments created by a different process.
	if err := netlink.LinkSetXdpFdWithFlags(iface, prog.FD(), int(flags)); err != nil {
		return fmt.Errorf("attaching XDP program %s to interface %s using netlink: %w", progName, iface.Attrs().Name, err)
	}

	// Nothing left to do, the netlink device now holds a reference to the prog
	// the program stays active.
	log.Infof("Program %s was attached using netlink", progName)

	return nil
}

// DetachXDP removes an XDP program from a network interface.
//
// bpffsBase is typically /sys/fs/bpf/cilium, but can be overridden to a tempdir
// during tests.
func DetachXDP(iface netlink.Link, bpffsBase, progName string) error {
	pin := filepath.Join(bpffsDeviceLinksDir(bpffsBase, iface), progName)
	err := bpf.UnpinLink(pin)
	if err == nil {
		return nil
	}

	if !errors.Is(err, os.ErrNotExist) {
		// The pinned link exists, something went wrong unpinning it.
		return fmt.Errorf("unpinning XDP program using bpf_link: %w", err)
	}

	// Pin doesn't exist, fall through to detaching using netlink.
	if err := netlink.LinkSetXdpFdWithFlags(iface, -1, int(link.XDPGenericMode)); err != nil {
		return fmt.Errorf("detaching generic-mode XDP program using netlink: %w", err)
	}

	if err := netlink.LinkSetXdpFdWithFlags(iface, -1, int(link.XDPDriverMode)); err != nil {
		return fmt.Errorf("detaching driver-mode XDP program using netlink: %w", err)
	}

	return nil
}
