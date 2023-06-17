// Package linux provides type information for the current kernel.
package linux

import (
	"errors"
	"fmt"
	"os"
	"sync"

	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/internal"
)

var kernelBTF struct {
	sync.RWMutex
	spec     *btf.Spec
	fallback bool
}

// FlushCaches removes any cached kernel type information.
func FlushCaches() {
	kernelBTF.Lock()
	defer kernelBTF.Unlock()

	kernelBTF.spec, kernelBTF.fallback = nil, false
}

// TypesNoCopy returns type information for the current kernel.
//
// The returned Spec must not be modified.
func TypesNoCopy() (*btf.Spec, error) {
	kernelBTF.RLock()
	spec := kernelBTF.spec
	kernelBTF.RUnlock()

	if spec != nil {
		return spec, nil
	}

	spec, _, err := types()
	return spec, err
}

func types() (*btf.Spec, bool, error) {
	kernelBTF.Lock()
	defer kernelBTF.Unlock()

	if kernelBTF.spec != nil {
		return kernelBTF.spec, kernelBTF.fallback, nil
	}

	fh, fallback, err := findVMLinuxBTF()
	if err != nil {
		return nil, false, err
	}
	defer fh.Close()

	spec, err := btf.LoadSpecFromReader(fh)
	if err != nil {
		return nil, false, err
	}

	kernelBTF.spec, kernelBTF.fallback = spec, fallback
	return spec, fallback, nil
}

const builtinVMLinuxBTFPath = "/sys/kernel/btf/vmlinux"

// findVMLinuxBTF searches for the BTF that describes the current kernel.
//
// fallback is true if the file was read from a fallback location outside
// of /sys/. This can happen on older kernels that have builtin BTF disabled.
//
// The caller is responsible for closing the returned file.
func findVMLinuxBTF() (_ *os.File, fallback bool, _ error) {
	fh, err := os.Open(builtinVMLinuxBTFPath)
	if err == nil {
		return fh, false, nil
	}

	release, err := internal.KernelRelease()
	if err != nil {
		return nil, false, err
	}

	// use same list of locations as libbpf
	// https://github.com/libbpf/libbpf/blob/9a3a42608dbe3731256a5682a125ac1e23bced8f/src/btf.c#L3114-L3122
	locations := []string{
		"/boot/vmlinux-%s",
		"/lib/modules/%s/vmlinux-%[1]s",
		"/lib/modules/%s/build/vmlinux",
		"/usr/lib/modules/%s/kernel/vmlinux",
		"/usr/lib/debug/boot/vmlinux-%s",
		"/usr/lib/debug/boot/vmlinux-%s.debug",
		"/usr/lib/debug/lib/modules/%s/vmlinux",
	}

	for _, loc := range locations {
		fh, err := os.Open(fmt.Sprintf(loc, release))
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		return fh, true, err
	}

	return nil, false, fmt.Errorf("no BTF found for kernel version %s: %w", release, internal.ErrNotSupported)
}
