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

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

func parentToAttachType(parent uint32) ebpf.AttachType {
	switch parent {
	case netlink.HANDLE_MIN_INGRESS:
		return ebpf.AttachTCXIngress
	case netlink.HANDLE_MIN_EGRESS:
		return ebpf.AttachTCXEgress
	}
	panic(fmt.Sprintf("invalid tc direction: %d", parent))
}

// upsertTCXProgram updates or creates a new tcx attachment for prog to device.
// Returns [link.ErrNotSupported] if tcx is not supported on the node.
func upsertTCXProgram(logger *slog.Logger, device netlink.Link, prog *ebpf.Program, progName, bpffsDir string, parent uint32) error {
	err := updateTCX(logger, prog, progName, bpffsDir)
	if err == nil {
		// Link was updated, nothing left to do.
		return nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		// Unrecoverable error, surface to the caller.
		return fmt.Errorf("updating tcx program: %w", err)
	}

	return attachTCX(logger, device, prog, progName, bpffsDir, parentToAttachType(parent))
}

// attachTCX creates a new tcx attachment for prog to device at the given attach
// type. It pins the resulting link object to progName in bpffsDir.
//
// progName is typically the Program's key in CollectionSpec.Programs.
func attachTCX(logger *slog.Logger, device netlink.Link, prog *ebpf.Program, progName, bpffsDir string, attach ebpf.AttachType) error {
	if err := bpf.MkdirBPF(bpffsDir); err != nil {
		return fmt.Errorf("creating bpffs link dir for tcx attachment to device %s: %w", device.Attrs().Name, err)
	}

	l, err := link.AttachTCX(link.TCXOptions{
		Program:   prog,
		Attach:    attach,
		Interface: device.Attrs().Index,
		Anchor:    link.Tail(),
	})
	if err != nil {
		return fmt.Errorf("attaching tcx: %w", err)
	}

	defer func() {
		// The program was successfully attached using tcx. Closing a link does not
		// detach the program if the link is pinned.
		if err := l.Close(); err != nil {
			logger.Warn("Failed to close tcx link for program",
				logfields.ProgName, progName,
			)
		}
	}()

	pin := filepath.Join(bpffsDir, progName)
	if err := l.Pin(pin); err != nil {
		return fmt.Errorf("pinning link at %s for program %s : %w", pin, progName, err)
	}

	logger.Info("Program attached to device using tcx",
		logfields.ProgName, progName,
		logfields.Device, device.Attrs().Name,
	)

	return nil
}

// updateTCX attempts to update an existing tcx link called progName in
// bpffsDir. If the link is defunct, the pin is removed.
//
// Returns nil if the update was successful. Returns an error wrapping
// [os.ErrNotExist] if the link is defunct or missing.
func updateTCX(logger *slog.Logger, prog *ebpf.Program, progName, bpffsDir string) error {
	// Attempt to open and update an existing link.
	pin := filepath.Join(bpffsDir, progName)
	err := bpf.UpdateLink(pin, prog)
	switch {
	// Link exists, but is defunct, and needs to be recreated. The program
	// no longer gets triggered at this point and the link needs to be removed
	// to proceed.
	case errors.Is(err, unix.ENOLINK):
		if err := os.Remove(pin); err != nil {
			return fmt.Errorf("unpinning defunct link %s: %w", pin, err)
		}

		logger.Info("Unpinned defunct link for program",
			logfields.Link, pin,
			logfields.ProgName, progName,
		)

		// Wrap in os.ErrNotExist so the caller needs to look for one error.
		return fmt.Errorf("unpinned defunct link: %w", os.ErrNotExist)

	// No existing link found, continue trying to create one.
	case errors.Is(err, os.ErrNotExist):
		logger.Debug("No existing link found for program",
			logfields.Link, pin,
			logfields.ProgName, progName,
		)
		return err

	case err != nil:
		return fmt.Errorf("updating link %s for program %s: %w", pin, progName, err)
	}

	logger.Info("Updated link for program",
		logfields.Link, pin,
		logfields.ProgName, progName,
	)
	return nil
}

// hasCiliumTCXLinks returns true if device has a Cilium-managed tcx program
// with the given attach type.
func hasCiliumTCXLinks(device netlink.Link, attach ebpf.AttachType) (bool, error) {
	result, err := link.QueryPrograms(link.QueryOptions{
		Target: int(device.Attrs().Index),
		Attach: attach,
	})
	if errors.Is(err, unix.EINVAL) {
		// Attach type likely not supported, kernel doesn't support tcx.
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("querying %s tcx programs for device %s: %w", attach, device.Attrs().Name, err)
	}
	if result == nil || len(result.Programs) == 0 {
		return false, nil
	}

	for _, p := range result.Programs {
		prog, err := ebpf.NewProgramFromID(p.ID)
		if err != nil {
			return false, fmt.Errorf("opening program with id %d: %w", p.ID, err)
		}
		defer prog.Close()

		pi, err := prog.Info()
		if err != nil {
			continue
		}
		if strings.HasPrefix(pi.Name, "cil_") {
			return true, nil
		}
	}

	return false, nil
}
