// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package loader

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/datapath/linux/safenetlink"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"
)

// attachSKBProgram attaches prog to device using tcx if available and enabled,
// or legacy tc as a fallback.
func attachSKBProgram(logger *slog.Logger, device netlink.Link, prog *ebpf.Program, progName, bpffsDir string, parent uint32, tcxEnabled bool) error {
	if prog == nil {
		return fmt.Errorf("program %s is nil", progName)
	}

	if tcxEnabled {
		// If the device is a netkit device, we know that netkit links are
		// supported, therefore use netkit instead of tcx. For all others like
		// host devices, rely on tcx.
		if device.Type() == "netkit" {
			if err := upsertNetkitProgram(logger, device, prog, progName, bpffsDir, parent); err != nil {
				return fmt.Errorf("attaching netkit program %s: %w", progName, err)
			}
			return nil
		}

		// Attach using tcx if available. This is seamless on interfaces with
		// existing tc programs since attaching tcx disables legacy tc evaluation.
		err := upsertTCXProgram(logger, device, prog, progName, bpffsDir, parent)
		if err == nil {
			// Created tcx link, clean up any leftover legacy tc attachments.
			if err := removeTCFilters(device, parent); err != nil {
				logger.Warn(
					"Cleaning up legacy tc after attaching tcx program",
					logfields.Error, err,
					logfields.ProgName, progName,
				)
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
	if err := upsertTCProgram(logger, device, prog, progName, parent, option.Config.TCFilterPriority); err != nil {
		return fmt.Errorf("attaching legacy tc program %s: %w", progName, err)
	}

	// Legacy tc attached, make sure tcx is detached in case of downgrade.
	// netkit can only be used in combination with tcx, but never legacy tc,
	// hence for netkit detaching here would be irrelevant.
	if err := detachGeneric(logger, bpffsDir, progName, "tcx"); err != nil {
		return fmt.Errorf("tcx cleanup after attaching legacy tc program %s: %w", progName, err)
	}

	return nil
}

func detachGeneric(logger *slog.Logger, bpffsDir, progName, what string) error {
	pin := filepath.Join(bpffsDir, progName)
	err := bpf.UnpinLink(pin)
	if err == nil {
		logger.Info("Removed link",
			logfields.Link, what,
			logfields.Pin, pin,
		)
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
func detachSKBProgram(logger *slog.Logger, device netlink.Link, progName, bpffsDir string, parent uint32) error {
	what := "tcx"
	if device.Type() == "netkit" {
		what = "netkit"
	}
	// Both tcx and netkit have pinned links which only need to be removed.
	// Approach is exactly the same.
	if err := detachGeneric(logger, bpffsDir, progName, what); err != nil {
		return err
	}

	return removeTCFilters(device, parent)
}

// upsertTCProgram attaches prog to device using a legacy tc bpf filter.
// Existing programs with the same name but different priority are detached
// after attaching the new program.
func upsertTCProgram(logger *slog.Logger, device netlink.Link, prog *ebpf.Program, progName string, parent uint32, prio uint16) error {
	if err := replaceQdisc(device); err != nil {
		return fmt.Errorf("replacing clsact qdisc for interface %s: %w", device.Attrs().Name, err)
	}

	// Leaving prio at 0 will cause the kernel to assign a priority in the higher
	// 16-bits region. If this happens, we're unable to read back the value we
	// specified in the request, i.e. when cleaning up leftover filters with a
	// different priority. Default to 1 to avoid surprises.
	if prio == 0 {
		prio = 1
	}

	filter := &netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: device.Attrs().Index,
			Parent:    parent,
			Handle:    1,
			Protocol:  unix.ETH_P_ALL,
			Priority:  prio,
		},
		Fd:           prog.FD(),
		Name:         fmt.Sprintf("%s-%s", progName, device.Attrs().Name),
		DirectAction: true,
	}

	if err := netlink.FilterReplace(filter); err != nil {
		return fmt.Errorf("replacing tc filter for interface %s: %w", device.Attrs().Name, err)
	}

	logger.Info(
		"Program attached to device using legacy tc",
		logfields.ProgName, progName,
		logfields.Priority, filter.Attrs().Priority,
		logfields.Device, device.Attrs().Name,
	)

	if err := removeStaleTCFilters(logger, device, parent, prio); err != nil {
		return fmt.Errorf("removing stale tc filter %s for interface %s: %w", filter.Name, device.Attrs().Name, err)
	}

	return nil
}

// removeStaleTCFilters removes all Cilium tc bpf filters from the given
// device with a different priority than the given new priority.
func removeStaleTCFilters(logger *slog.Logger, device netlink.Link, parent uint32, newPrio uint16) error {
	filters, err := safenetlink.FilterList(device, parent)
	if err != nil {
		return err
	}

	for _, f := range filters {
		old, ok := f.(*netlink.BpfFilter)
		if !ok {
			continue
		}

		// Don't touch filters belonging to other programs.
		if !isCiliumFilter(old) {
			continue
		}

		// Don't remove filters with the new priority.
		if old.Priority == newPrio {
			continue
		}

		if err := netlink.FilterDel(f); err != nil {
			return err
		}

		logger.Info(
			"Deleted stale tc bpf filter",
			logfields.ProgName, old.Name,
			logfields.Priority, old.Priority,
			logfields.Device, device.Attrs().Name,
		)
	}

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
			if isCiliumFilter(bpfFilter) {
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

func isCiliumFilter(filter *netlink.BpfFilter) bool {
	return strings.HasPrefix(filter.Name, "cil_")
}
