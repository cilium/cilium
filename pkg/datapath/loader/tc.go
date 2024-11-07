// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package loader

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/datapath/linux/safenetlink"
	"github.com/cilium/cilium/pkg/option"
)

// attachSKBProgram attaches prog to device using tcx if available and enabled,
// or legacy tc as a fallback.
func attachSKBProgram(device netlink.Link, prog *ebpf.Program, progName, bpffsDir string, parent uint32, tcxEnabled bool) error {
	if prog == nil {
		return fmt.Errorf("program %s is nil", progName)
	}

	if tcxEnabled {
		// If the device is a netkit device, we know that netkit links are
		// supported, therefore use netkit instead of tcx. For all others like
		// host devices, rely on tcx.
		if device.Type() == "netkit" {
			if err := upsertNetkitProgram(device, prog, progName, bpffsDir, parent); err != nil {
				return fmt.Errorf("attaching netkit program %s: %w", progName, err)
			}
			return nil
		}

		// Attach using tcx if available. This is seamless on interfaces with
		// existing tc programs since attaching tcx disables legacy tc evaluation.
		err := upsertTCXProgram(device, prog, progName, bpffsDir, parent)
		if err == nil {
			// Created tcx link, clean up any leftover legacy tc attachments.
			if err := removeTCFilters(device, parent); err != nil {
				log.WithError(err).Warnf("Cleaning up legacy tc after attaching tcx program %s", progName)
			}
			// Don't fall back to legacy tc.
			return nil
		}
		if !errors.Is(err, link.ErrNotSupported) {
			// Unrecoverable error, surface to the caller.
			return fmt.Errorf("attaching tcx program %s: %w", progName, err)
		}
	}

	// tcx not available or disabled, fall back to legacy tc.
	if err := attachTCProgram(device, prog, progName, parent); err != nil {
		return fmt.Errorf("attaching legacy tc program %s: %w", progName, err)
	}

	// Legacy tc attached, make sure tcx is detached in case of downgrade.
	// netkit can only be used in combination with tcx, but never legacy tc,
	// hence for netkit detaching here would be irrelevant.
	if err := detachGeneric(bpffsDir, progName, "tcx"); err != nil {
		return fmt.Errorf("tcx cleanup after attaching legacy tc program %s: %w", progName, err)
	}

	return nil
}

func detachGeneric(bpffsDir, progName, what string) error {
	pin := filepath.Join(bpffsDir, progName)
	err := bpf.UnpinLink(pin)
	if err == nil {
		log.Infof("Removed %s link at %s", what, pin)
		return nil
	}
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}

	// The pinned link exists, something went wrong unpinning it.
	return fmt.Errorf("unpinning %s link: %w", what, err)
}

// detachSKBProgram attempts to remove an existing tcx, netkit and legacy tc link
// with the given properties. Always attempts to remove all three attachments.
func detachSKBProgram(device netlink.Link, progName, bpffsDir string, parent uint32) error {
	what := "tcx"
	if device.Type() == "netkit" {
		what = "netkit"
	}
	// Both tcx and netkit have pinned links which only need to be removed.
	// Approach is exactly the same.
	if err := detachGeneric(bpffsDir, progName, what); err != nil {
		return err
	}

	return removeTCFilters(device, parent)
}

// attachTCProgram attaches prog to device using a legacy tc bpf filter.
func attachTCProgram(device netlink.Link, prog *ebpf.Program, progName string, parent uint32) error {
	if err := replaceQdisc(device); err != nil {
		return fmt.Errorf("replacing clsact qdisc for interface %s: %w", device.Attrs().Name, err)
	}

	filter := &netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: device.Attrs().Index,
			Parent:    parent,
			Handle:    1,
			Protocol:  unix.ETH_P_ALL,
			Priority:  option.Config.TCFilterPriority,
		},
		Fd:           prog.FD(),
		Name:         fmt.Sprintf("%s-%s", progName, device.Attrs().Name),
		DirectAction: true,
	}

	if err := netlink.FilterReplace(filter); err != nil {
		return fmt.Errorf("replacing tc filter for interface %s: %w", device.Attrs().Name, err)
	}

	log.Infof("Program %s attached to device %s using legacy tc", progName, device.Attrs().Name)

	return nil
}

// removeTCFilters removes all tc filters from the given interface.
// Direction is passed as netlink.HANDLE_MIN_{INGRESS,EGRESS} via parent.
func removeTCFilters(device netlink.Link, parent uint32) error {
	filters, err := safenetlink.FilterList(device, parent)
	if err != nil {
		return err
	}

	for _, f := range filters {
		if err := netlink.FilterDel(f); err != nil {
			return err
		}
	}

	return nil
}

// hasCiliumTCFilters returns true if device has Cilium-managed bpf filters
// for the given direction (parent).
func hasCiliumTCFilters(device netlink.Link, parent uint32) (bool, error) {
	filters, err := safenetlink.FilterList(device, parent)
	if err != nil {
		return false, fmt.Errorf("listing tc filters for device %s, direction %d: %w", device.Attrs().Name, parent, err)
	}

	for _, f := range filters {
		if bpfFilter, ok := f.(*netlink.BpfFilter); ok {
			// If any filter contains the cil_ prefix in the name we know Cilium
			// previously attached its programs to this netlink device.
			if strings.HasPrefix(bpfFilter.Name, "cil_") {
				return true, nil
			}
		}
	}

	return false, nil
}

func replaceQdisc(link netlink.Link) error {
	attrs := netlink.QdiscAttrs{
		LinkIndex: link.Attrs().Index,
		Handle:    netlink.MakeHandle(0xffff, 0),
		Parent:    netlink.HANDLE_CLSACT,
	}

	qdisc := &netlink.GenericQdisc{
		QdiscAttrs: attrs,
		QdiscType:  qdiscClsact,
	}

	return netlink.QdiscReplace(qdisc)
}
