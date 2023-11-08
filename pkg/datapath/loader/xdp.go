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
	"github.com/vishvananda/netlink/nl"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/mac"
	"github.com/cilium/cilium/pkg/option"
)

func xdpModeToFlag(xdpMode string) uint32 {
	switch xdpMode {
	case option.XDPModeNative:
		return nl.XDP_FLAGS_DRV_MODE
	case option.XDPModeGeneric:
		return nl.XDP_FLAGS_SKB_MODE
	case option.XDPModeLinkDriver:
		return nl.XDP_FLAGS_DRV_MODE
	case option.XDPModeLinkGeneric:
		return nl.XDP_FLAGS_SKB_MODE
	}
	return 0
}

// maybeUnloadObsoleteXDPPrograms removes bpf_xdp.o from previously used devices.
func maybeUnloadObsoleteXDPPrograms(xdpDevs []string, xdpMode string) {
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
				linkxdp.AttachMode == xdpModeToFlag(xdpMode) {
				// XDP mode matches; don't unload, otherwise we might introduce
				// intermittent connectivity problems
				used = true
				break
			}
		}
		if !used {
			netlink.LinkSetXdpFdWithFlags(link, -1, int(xdpModeToFlag(option.XDPModeLinkGeneric)))
			netlink.LinkSetXdpFdWithFlags(link, -1, int(xdpModeToFlag(option.XDPModeLinkDriver)))
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
