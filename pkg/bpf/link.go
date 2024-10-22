// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package bpf

import (
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

// UpdateLink loads a pinned bpf_link at the given pin path and updates its
// program.
//
// Returns [os.ErrNotExist] if the pin is not found.
//
// Updating the link can fail if it is defunct (the hook it points to no longer
// exists).
func UpdateLink(pin string, prog *ebpf.Program) error {
	l, err := link.LoadPinnedLink(pin, &ebpf.LoadPinOptions{})
	if err != nil {
		return fmt.Errorf("opening pinned link %s: %w", pin, err)
	}
	defer l.Close()

	if err = l.Update(prog); err != nil {
		return fmt.Errorf("updating link %s: %w", pin, err)
	}
	return nil
}

// DetachLink loads and unpins a bpf_link at the given pin path.
//
// Returns [os.ErrNotExist] if the pin is not found.
func UnpinLink(pin string) error {
	l, err := link.LoadPinnedLink(pin, &ebpf.LoadPinOptions{})
	if err != nil {
		return fmt.Errorf("opening pinned link %s: %w", pin, err)
	}
	defer l.Close()

	if err := l.Unpin(); err != nil {
		return fmt.Errorf("unpinning link %s: %w", pin, err)
	}
	return nil
}
