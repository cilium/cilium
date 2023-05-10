// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package probes

import (
	"errors"

	"golang.org/x/sys/unix"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/features"

	"github.com/cilium/cilium/pkg/lock"
)

// HaveAttachType returns nil if the given program/attach type combination is
// supported by the underlying kernel. Returns ebpf.ErrNotSupported if loading a
// program with the given Program/AttachType fails. If the probe is inconclusive
// due to an unrecognized return code, the original error is returned.
//
// Note that program types that don't use attach types will silently succeed if
// an attach type is specified.
//
// Probe results are cached by the package and shouldn't be memoized by the
// caller.
func HaveAttachType(pt ebpf.ProgramType, at ebpf.AttachType) (err error) {
	if err := features.HaveProgramType(pt); err != nil {
		return err
	}

	attachProbesMu.Lock()
	defer attachProbesMu.Unlock()
	if err, ok := attachProbes[attachProbe{pt, at}]; ok {
		return err
	}

	defer func() {
		// Closes over named return variable err to cache any returned errors.
		attachProbes[attachProbe{pt, at}] = err
	}()

	spec := &ebpf.ProgramSpec{
		Type:       pt,
		AttachType: at,
		Instructions: asm.Instructions{
			// recvmsg and peername require a return value of 1, use it for all probes.
			asm.LoadImm(asm.R0, 1, asm.DWord),
			asm.Return(),
		},
	}

	prog, err := ebpf.NewProgramWithOptions(spec, ebpf.ProgramOptions{
		LogDisabled: true,
	})
	if err == nil {
		prog.Close()
	}

	// EINVAL occurs when attempting to create a program with an unknown type.
	// E2BIG occurs when ProgLoadAttr contains non-zero bytes past the end
	// of the struct known by the running kernel, meaning the kernel is too old
	// to support the given prog type.
	if errors.Is(err, unix.EINVAL) || errors.Is(err, unix.E2BIG) {
		err = ebpf.ErrNotSupported
	}
	if err != nil {
		return err
	}

	return nil
}

type attachProbe struct {
	pt ebpf.ProgramType
	at ebpf.AttachType
}

var attachProbesMu lock.Mutex
var attachProbes map[attachProbe]error = make(map[attachProbe]error)
