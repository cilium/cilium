// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package probes

import (
	"errors"
	"fmt"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"
)

// HaveAttachCgroup returns nil if the kernel is compiled with
// CONFIG_CGROUP_BPF.
//
// It's only an approximation and doesn't execute a successful cgroup attachment
// under the hood. If any unexpected errors are encountered, the original error
// is returned.
func HaveAttachCgroup() error {
	attachCgroupOnce.Do(func() {
		attachCgroupResult = haveAttachCgroup()
	})

	return attachCgroupResult
}

func haveAttachCgroup() error {
	// Load known-good program supported by the earliest kernels with cgroup
	// support.
	spec := &ebpf.ProgramSpec{
		Type:       ebpf.CGroupSKB,
		AttachType: ebpf.AttachCGroupInetIngress,
		Instructions: asm.Instructions{
			asm.LoadImm(asm.R0, 0, asm.DWord),
			asm.Return(),
		},
	}

	p, err := ebpf.NewProgramWithOptions(spec, ebpf.ProgramOptions{
		LogDisabled: true,
	})
	if err != nil {
		return fmt.Errorf("create cgroup program: %w: %w", err, ebpf.ErrNotSupported)
	}
	defer p.Close()

	// Attaching to a non-cgroup node should result in EBADF when creating the
	// link, compared to EINVAL if the kernel does not support or was compiled
	// without CONFIG_CGROUP_BPF.
	_, err = link.AttachCgroup(link.CgroupOptions{Path: "/dev/null", Program: p, Attach: spec.AttachType})
	if errors.Is(err, unix.EBADF) {
		// The kernel checked the given file descriptor from within the cgroup prog
		// attach handler. Assume it supports attaching cgroup progs.
		return nil
	}
	if err != nil {
		// Preserve the original error in the error string. Needs Go 1.20.
		return fmt.Errorf("link cgroup program to /dev/null: %w: %w", err, ebpf.ErrNotSupported)
	}

	return errors.New("attaching prog to /dev/null did not result in error")
}

var attachCgroupOnce sync.Once
var attachCgroupResult error
