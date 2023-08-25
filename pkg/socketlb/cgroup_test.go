// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package socketlb

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/link"

	"github.com/cilium/cilium/pkg/testutils"
)

func mustCgroupProgram(t *testing.T) *ebpf.Program {
	p, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		Type: ebpf.CGroupSKB,
		Instructions: asm.Instructions{
			asm.Mov.Imm(asm.R0, 0),
			asm.Return(),
		},
		License: "Apache-2.0",
	})
	if err != nil {
		t.Skipf("cgroup programs not supported: %s", err)
	}
	return p
}

// Attach a program to a clean cgroup hook, no replacing necessary.
func TestAttachCgroup(t *testing.T) {
	testutils.PrivilegedTest(t)

	coll := &ebpf.Collection{
		Programs: map[string]*ebpf.Program{"test": mustCgroupProgram(t)},
	}
	linkPath := testutils.TempBPFFS(t)
	cgroupPath := testutils.TempCgroup(t)

	if err := attachCgroup(coll, "test", cgroupPath, linkPath); err != nil {
		t.Fatal(err)
	}

	if err := detachCgroup("test", cgroupPath, linkPath); err != nil {
		t.Fatal(err)
	}
}

// Replace an existing program attached using PROG_ATTACH. On newer kernels,
// this will attempt to replace a PROG_ATTACH with a bpf_link.
func TestAttachCgroupWithPreviousAttach(t *testing.T) {
	testutils.PrivilegedTest(t)

	prog := mustCgroupProgram(t)
	coll := &ebpf.Collection{
		Programs: map[string]*ebpf.Program{"test": prog},
	}

	linkPath := testutils.TempBPFFS(t)
	cgroupPath := testutils.TempCgroup(t)
	f, err := os.Open(cgroupPath)
	if err != nil {
		t.Fatal(err)
	}

	if err := link.RawAttachProgram(link.RawAttachProgramOptions{
		Target:  int(f.Fd()),
		Program: prog,
		// Dummy attach type, must match the conclusion made by attachCgroup.
		Attach: ebpf.AttachCGroupInetIngress,
	}); err != nil {
		t.Fatal(err)
	}

	if err := attachCgroup(coll, "test", cgroupPath, linkPath); err != nil {
		t.Fatal(err)
	}

	if err := detachCgroup("test", cgroupPath, linkPath); err != nil {
		t.Fatal(err)
	}
}

// On kernels that support it, update a bpf_link attachment by opening a pin.
func TestAttachCgroupWithExistingLink(t *testing.T) {
	testutils.PrivilegedTest(t)

	prog := mustCgroupProgram(t)
	coll := &ebpf.Collection{
		Programs: map[string]*ebpf.Program{"test": prog},
	}

	linkPath := testutils.TempBPFFS(t)
	cgroupPath := testutils.TempCgroup(t)
	f, err := os.Open(cgroupPath)
	if err != nil {
		t.Fatal(err)
	}

	l, err := link.AttachRawLink(link.RawLinkOptions{
		Target:  int(f.Fd()),
		Program: prog,
		// Dummy attach type, must match the conclusion made by attachCgroup.
		Attach: ebpf.AttachCGroupInetIngress,
	})
	if errors.Is(err, ebpf.ErrNotSupported) {
		t.Skip("bpf_link is not supported")
	}
	if err != nil {
		t.Fatal(err)
	}

	if err := l.Pin(filepath.Join(linkPath, "test")); err != nil {
		t.Fatal(err)
	}

	if err := attachCgroup(coll, "test", cgroupPath, linkPath); err != nil {
		t.Fatal(err)
	}

	if err := detachCgroup("test", cgroupPath, linkPath); err != nil {
		t.Fatal(err)
	}
}

// Detach an existing PROG_ATTACH.
func TestDetachCGroupWithPreviousAttach(t *testing.T) {
	testutils.PrivilegedTest(t)

	prog := mustCgroupProgram(t)
	linkPath := testutils.TempBPFFS(t)
	cgroupPath := testutils.TempCgroup(t)
	f, err := os.Open(cgroupPath)
	if err != nil {
		t.Fatal(err)
	}

	if err := link.RawAttachProgram(link.RawAttachProgramOptions{
		Target:  int(f.Fd()),
		Program: prog,
		// Dummy attach type, must match the conclusion made by attachCgroup.
		Attach: ebpf.AttachCGroupInetIngress,
	}); err != nil {
		t.Fatal(err)
	}

	if err := detachCgroup("test", cgroupPath, linkPath); err != nil {
		t.Fatal(err)
	}
}

// Detach an existing bpf_link.
func TestDetachCGroupWithExistingLink(t *testing.T) {
	testutils.PrivilegedTest(t)

	prog := mustCgroupProgram(t)
	linkPath := testutils.TempBPFFS(t)
	cgroupPath := testutils.TempCgroup(t)
	f, err := os.Open(cgroupPath)
	if err != nil {
		t.Fatal(err)
	}

	l, err := link.AttachRawLink(link.RawLinkOptions{
		Target:  int(f.Fd()),
		Program: prog,
		// Dummy attach type, must match the conclusion made by attachCgroup.
		Attach: ebpf.AttachCGroupInetIngress,
	})
	if errors.Is(err, ebpf.ErrNotSupported) {
		t.Skip("bpf_link is not supported")
	}
	if err != nil {
		t.Fatal(err)
	}
	if err := l.Pin(filepath.Join(linkPath, "test")); err != nil {
		t.Fatal(err)
	}

	if err := detachCgroup("test", cgroupPath, linkPath); err != nil {
		t.Fatal(err)
	}
}
