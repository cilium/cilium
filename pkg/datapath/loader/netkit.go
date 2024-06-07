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

func parentToNetkitType(parent uint32) ebpf.AttachType {
	switch parent {
	// tc ingress on a veth host device of a Pod is the logical egress
	// direction. Thus this must get attached to the xmit of the netkit
	// peer device inside the Pod.
	case netlink.HANDLE_MIN_INGRESS:
		return ebpf.AttachNetkitPeer
	// tc egress on a veth host device of a Pod is the logical ingress
	// direction. Thus this must get attached to the xmit of the netkit
	// primary device in the host namespace.
	case netlink.HANDLE_MIN_EGRESS:
		return ebpf.AttachNetkitPrimary
	}
	panic(fmt.Sprintf("invalid tc direction: %d", parent))
}

// upsertNetkitProgram updates or creates a new netkit attachment for prog to
// device. Returns [link.ErrNotSupported] if netkit is not supported on the node.
func upsertNetkitProgram(device netlink.Link, prog *ebpf.Program, progName, bpffsDir string, parent uint32) error {
	err := updateNetkit(prog, progName, bpffsDir)
	if err == nil {
		// Link was updated, nothing left to do.
		return nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		// Unrecoverable error, surface to the caller.
		return fmt.Errorf("updating netkit program: %w", err)
	}

	return attachNetkit(device, prog, progName, bpffsDir, parentToNetkitType(parent))
}

// attachNetkit attaches the tc BPF prog to the netkit device. It pins the
// resulting link object to progName in bpffsDir, similar to tcx.
//
// progName is typically the Program's key in CollectionSpec.Programs.
//
// attach is either ebpf.AttachNetkitPrimary or ebpf.AttachNetkitPeer and
// will attach the program to the xmit of either the primary or peer device.
func attachNetkit(device netlink.Link, prog *ebpf.Program, progName, bpffsDir string, attach ebpf.AttachType) error {
	if err := bpf.MkdirBPF(bpffsDir); err != nil {
		return fmt.Errorf("creating bpffs link dir for netkit attachment to device %s: %w", device.Attrs().Name, err)
	}

	l, err := link.AttachNetkit(link.NetkitOptions{
		Program:   prog,
		Attach:    attach,
		Interface: device.Attrs().Index,
		Anchor:    link.Tail(),
	})
	if err != nil {
		return fmt.Errorf("attaching netkit: %w", err)
	}

	defer func() {
		// The program was successfully attached using netkit. Closing
		// a link does not detach the program if the link is pinned.
		if err := l.Close(); err != nil {
			log.Warnf("Failed to close netkit link for program %s", progName)
		}
	}()

	pin := filepath.Join(bpffsDir, progName)
	if err := l.Pin(pin); err != nil {
		return fmt.Errorf("pinning link at %s for program %s : %w", pin, progName, err)
	}

	log.Infof("Program %s attached to device %s using netkit", progName, device.Attrs().Name)

	return nil
}

// updateNetkit attempts to update an existing netkit link called progName
// in bpffsDir. If the link is defunct, the pin is removed.
//
// Returns nil if the update was successful. Returns an error wrapping
// [os.ErrNotExist] if the link is defunct or missing.
func updateNetkit(prog *ebpf.Program, progName, bpffsDir string) error {
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

		log.Infof("Unpinned defunct link %s for program %s", pin, progName)

		// Wrap in os.ErrNotExist so the caller needs to look for one error.
		return fmt.Errorf("unpinned defunct link: %w", os.ErrNotExist)

	// No existing link found, continue trying to create one.
	case errors.Is(err, os.ErrNotExist):
		log.Debugf("No existing link found at %s for program %s", pin, progName)
		return err

	case err != nil:
		return fmt.Errorf("updating link %s for program %s: %w", pin, progName, err)
	}

	log.Infof("Updated link %s for program %s", pin, progName)
	return nil
}

// hasCiliumNetkitLinks returns true if device has a Cilium-managed
// netkit program with the given attach type.
func hasCiliumNetkitLinks(device netlink.Link, attach ebpf.AttachType) (bool, error) {
	if device.Type() != "netkit" {
		// Not a netkit device, therefore also no netkit links.
		return false, nil
	}
	result, err := link.QueryPrograms(link.QueryOptions{
		Target: int(device.Attrs().Index),
		Attach: attach,
	})
	if errors.Is(err, unix.EINVAL) {
		// Attach type likely not supported, kernel doesn't support netkit.
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("querying %s netkit programs for device %s: %w", attach, device.Attrs().Name, err)
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
