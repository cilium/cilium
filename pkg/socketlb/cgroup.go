// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

// attachCgroup and detachCgroup have to deal with two different kernel APIs:
//
// bpf_link (available with kernel version >= 5.7): in order for the program<->cgroup
// association to outlive the userspace process, the link (not the program) needs to be pinned.
// Removing the pinned link on bpffs breaks the association.
// Cilium will only use links on fresh installs and if available in the kernel.
// On upgrade, a link can be updated using link.Update(), which will atomically replace the
// currently running bpf program.
//
// PROG_ATTACH (all kernel versions pre 5.7 that cilium supports): by definition the association
// outlives userspace as the cgroup will hold a reference  to the attached program and detaching
// must be done explicitly using PROG_DETACH.
// This API is what cilium has been using prior to the 1.14 release and will continue to use if
// bpf_link is not available.
// On upgrade, cilium will continue to seamlessly replace old programs with the PROG_ATTACH API,
// because updating it with a bpf_link could cause connectivity interruptions.

package socketlb

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"
)

var attachTypes = map[string]ebpf.AttachType{
	Connect4:     ebpf.AttachCGroupInet4Connect,
	SendMsg4:     ebpf.AttachCGroupUDP4Sendmsg,
	RecvMsg4:     ebpf.AttachCGroupUDP4Recvmsg,
	GetPeerName4: ebpf.AttachCgroupInet4GetPeername,
	PostBind4:    ebpf.AttachCGroupInet4PostBind,
	PreBind4:     ebpf.AttachCGroupInet4Bind,
	Connect6:     ebpf.AttachCGroupInet6Connect,
	SendMsg6:     ebpf.AttachCGroupUDP6Sendmsg,
	RecvMsg6:     ebpf.AttachCGroupUDP6Recvmsg,
	GetPeerName6: ebpf.AttachCgroupInet6GetPeername,
	PostBind6:    ebpf.AttachCGroupInet6PostBind,
	PreBind6:     ebpf.AttachCGroupInet6Bind,
}

// attachCgroup attaches a program from spec with the given name to cgroupRoot.
// If the kernel supports it, the resulting bpf_link is pinned to pinPath.
//
// Upgrades from prior Cilium versions will continue to be handled by a PROG_ATTACH
// to replace an old program attached to a cgroup.
func attachCgroup(spec *ebpf.Collection, name, cgroupRoot, pinPath string) error {
	prog := spec.Programs[name]
	if prog == nil {
		return fmt.Errorf("program %s not found in ELF", name)
	}

	// Attempt to open and update an existing link.
	pin := filepath.Join(pinPath, name)
	err := updateLink(pin, prog)
	switch {
	// Update successful, nothing left to do.
	case err == nil:
		log.Infof("Updated link %s for program %s", pin, name)

		return nil

	// Link exists, but is defunct, and needs to be recreated against a new
	// cgroup. This can happen in environments like dind where we're attaching
	// to a sub-cgroup that goes away if the container is destroyed, but the
	// link persists in the host's /sys/fs/bpf. The program no longer gets
	// triggered at this point and the link needs to be removed to proceed.
	case errors.Is(err, unix.ENOLINK):
		if err := os.Remove(pin); err != nil {
			return fmt.Errorf("unpinning defunct link %s: %w", pin, err)
		}

		log.Infof("Unpinned defunct link %s for program %s", pin, name)

	// No existing link found, continue trying to create one.
	case errors.Is(err, os.ErrNotExist):
		log.Infof("No existing link found at %s for program %s", pin, name)

	default:
		return fmt.Errorf("updating link %s for program %s: %w", pin, name, err)
	}

	cg, err := os.Open(cgroupRoot)
	if err != nil {
		return fmt.Errorf("open cgroup %s: %w", cgroupRoot, err)
	}
	defer cg.Close()

	// Create a new link. This will only succeed on nodes that support bpf_link
	// and don't have any attached PROG_ATTACH programs.
	l, err := link.AttachRawLink(link.RawLinkOptions{
		Target:  int(cg.Fd()),
		Program: prog,
		Attach:  attachTypes[name],
	})
	if err == nil {
		defer func() {
			// The program was successfully attached using bpf_link. Closing a link
			// does not detach the program if the link is pinned.
			if err := l.Close(); err != nil {
				log.Warnf("Failed to close bpf_link for program %s", name)
			}
		}()

		if err := l.Pin(pin); err != nil {
			return fmt.Errorf("pin link at %s for program %s : %w", pin, name, err)
		}

		// Successfully created and pinned bpf_link.
		log.Debugf("Program %s attached using bpf_link", name)

		return nil
	}

	// Kernels before 5.7 don't support bpf_link. In that case link.AttachRawLink
	// returns ErrNotSupported.
	//
	// If the kernel supports bpf_link, but an older version of Cilium attached a
	// cgroup program without flags (old init.sh behaviour), link.AttachRawLink
	// will return EPERM because bpf_link implicitly uses the multi flag.
	if !errors.Is(err, unix.EPERM) && !errors.Is(err, link.ErrNotSupported) {
		// Unrecoverable error from AttachRawLink.
		return fmt.Errorf("attach program %s using bpf_link: %w", name, err)
	}

	log.Debugf("Performing PROG_ATTACH for program %s", name)

	// Call PROG_ATTACH without flags to attach the program if bpf_link is not
	// available or a previous PROG_ATTACH without flags has to be seamlessly
	// replaced.
	if err := link.RawAttachProgram(link.RawAttachProgramOptions{
		Target:  int(cg.Fd()),
		Program: prog,
		Attach:  attachTypes[name],
	}); err != nil {
		return fmt.Errorf("PROG_ATTACH for program %s: %w", name, err)
	}

	// Nothing left to do, the cgroup now holds a reference to the prog
	// so we don't need to hold a reference in the agent/bpffs to ensure
	// the program stays active.
	log.Debugf("Program %s was attached using PROG_ATTACH", name)

	return nil

}

// updateLink opens a link at the given pin path and updates its program.
func updateLink(pin string, prog *ebpf.Program) error {
	l, err := link.LoadPinnedLink(pin, &ebpf.LoadPinOptions{})
	if err != nil {
		return fmt.Errorf("opening pinned link %s: %w", pin, err)
	}
	defer l.Close()

	// Attempt to update the link. This can fail if the link is defunct (the
	// cgroup it points to no longer exists).
	if err = l.Update(prog); err != nil {
		return fmt.Errorf("update link %s: %w", pin, err)
	}

	return nil
}

// detachCgroup detaches a program with the given name from cgroupRoot. Attempts
// to open a pinned link with the given name from directory pinPath first,
// falling back to PROG_DETACH if no pin is present.
func detachCgroup(name, cgroupRoot, pinPath string) error {
	pin := filepath.Join(pinPath, name)
	l, err := link.LoadPinnedLink(pin, &ebpf.LoadPinOptions{})
	if err == nil {
		if err := l.Unpin(); err != nil {
			return fmt.Errorf("unpin link %s: %w", pin, err)
		}
		if err := l.Close(); err != nil {
			return fmt.Errorf("close link %s: %w", name, err)
		}
		return nil
	}

	// No bpf_link pin found, detach all prog_attach progs.
	log.Debugf("No pinned link '%s', querying cgroup", pin)
	err = detachAll(attachTypes[name], cgroupRoot)
	// Treat detaching unsupported attach types as successful.
	if errors.Is(err, link.ErrNotSupported) {
		return nil
	}
	return err
}

// detachAll detaches all programs attached to cgroupRoot with the corresponding attach type.
func detachAll(attach ebpf.AttachType, cgroupRoot string) error {
	// Query the program ids of all programs currently attached to the given cgroup
	// with the given attach type. In ciliums case this should always return only one id.
	ids, err := link.QueryPrograms(link.QueryOptions{
		Path:   cgroupRoot,
		Attach: attach,
	})
	// We know the cgroup root exists, so EINVAL will likely mean querying
	// the given attach type is not supported.
	if errors.Is(err, unix.EINVAL) {
		err = fmt.Errorf("%s: %w", err, link.ErrNotSupported)
	}
	if err != nil {
		return fmt.Errorf("query cgroup %s for type %s: %w", cgroupRoot, attach, err)
	}

	if len(ids) == 0 {
		log.Debugf("No programs in cgroup %s with attach type %s", cgroupRoot, attach)
		return nil
	}

	cg, err := os.Open(cgroupRoot)
	if err != nil {
		return fmt.Errorf("open cgroup %s: %w", cg.Name(), err)
	}
	defer cg.Close()

	// cilium owns the cgroup and assumes only one program is attached.
	// This allows to remove all ids returned in the query phase.
	for _, id := range ids {
		prog, err := ebpf.NewProgramFromID(id)
		if err != nil {
			return fmt.Errorf("could not open program id %d: %w", id, err)
		}
		defer prog.Close()

		if err := link.RawDetachProgram(link.RawDetachProgramOptions{
			Target:  int(cg.Fd()),
			Program: prog,
			Attach:  attach,
		}); err != nil {
			return fmt.Errorf("detach programs from cgroup %s attach type %s: %w", cgroupRoot, attach, err)
		}

		log.Debugf("Detached program id %d", id)
	}

	return nil
}
