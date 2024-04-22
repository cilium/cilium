// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package loader

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/vishvananda/netlink"

	"github.com/cilium/cilium/pkg/bpf"
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

// attachTCX attaches prog to device at the given attach type using tcx. It pins
// the resulting link object to progName in bpffsDir.
//
// progName is typically the Program's key in CollectionSpec.Programs.
func attachTCX(device netlink.Link, prog *ebpf.Program, progName, bpffsDir string, attach ebpf.AttachType) error {
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
			log.Warnf("Failed to close tcx link for program %s", progName)
		}
	}()

	pin := filepath.Join(bpffsDir, progName)
	if err := l.Pin(pin); err != nil {
		return fmt.Errorf("pinning link at %s for program %s : %w", pin, progName, err)
	}

	log.Infof("Program %s attached to device %s using tcx", progName, device.Attrs().Name)

	return nil
}

// updateTCX attempts to update an existing tcx link called progName in
// bpffsDir. If the link is defunct, the pin is removed.
//
// Returns nil if the update was successful. Returns an error wrapping
// [os.ErrNotExist] if the link is defunct or missing.
func updateTCX(prog *ebpf.Program, progName, bpffsDir string) error {
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

		// Wrap in os.ErrNotExist so the caller needs to look for one error.
		err = fmt.Errorf("unpinned defunct link: %w", os.ErrNotExist)

	// No existing link found, continue trying to create one.
	case errors.Is(err, os.ErrNotExist):
		log.Infof("No existing link found at %s for program %s", pin, progName)

	default:
		return fmt.Errorf("updating link %s for program %s: %w", pin, progName, err)
	}

	return err
}

// detachTCX attempts to open the link at progName in bpffsDir and unpins it.
// Only returns unrecoverable errors. Returns nil if the link doesn't exist or
// if removal was successful.
func detachTCX(bpffsDir, progName string) error {
	pin := filepath.Join(bpffsDir, progName)
	err := bpf.UnpinLink(pin)
	if err == nil {
		log.Debugf("Removed pinned link at %s", pin)
		return nil
	}
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}

	// The pinned link exists, something went wrong unpinning it.
	return fmt.Errorf("unpinning tcx link: %w", err)
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
