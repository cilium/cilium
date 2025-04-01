// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package loader

import (
	"fmt"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/maps/lbmap"

	"github.com/cilium/ebpf"
)

var (
	BPFSockTermPath = "/bpf/bpf_sock_term.o"
)

type sockTermObjects struct {
	SockUDPDestroy *ebpf.Program `ebpf:"cil_sock_udp_destroy"`
}

// LoadSockTerm configures and loads the cil_sock_udp_destroy program and pins
// it to the given pinPath, if provided. If pinPath is empty, the program is
// pinned to the default pin path.
func LoadSockTerm(pinPath string) (*ebpf.Program, error) {
	spec, err := bpf.LoadCollectionSpec(BPFSockTermPath)
	if err != nil {
		return nil, fmt.Errorf("load eBPF ELF: %w", err)
	}

	// Since we don't compile bpf_sock_term.o at runtime, we need to adjust
	// MaxEntries for both maps to match the sizes defined in bpf_sock.c.
	if m := spec.Maps[lbmap.SockRevNat4MapName]; m == nil {
		return nil, fmt.Errorf("%s map not found in spec", lbmap.SockRevNat4MapName)
	} else {
		m.MaxEntries = uint32(lbmap.MaxSockRevNat4MapEntries)
	}

	if m := spec.Maps[lbmap.SockRevNat6MapName]; m == nil {
		return nil, fmt.Errorf("%s map not found in spec", lbmap.SockRevNat6MapName)
	} else {
		m.MaxEntries = uint32(lbmap.MaxSockRevNat6MapEntries)
	}

	if pinPath == "" {
		pinPath = bpf.TCGlobalsPath()
	}

	var obj sockTermObjects
	commit, err := bpf.LoadAndAssign(&obj, spec, &bpf.CollectionOptions{
		CollectionOptions: ebpf.CollectionOptions{
			Maps: ebpf.MapOptions{PinPath: pinPath},
		},
	})

	if err != nil {
		return nil, fmt.Errorf("loading program: %w", err)
	}

	if err := commit(); err != nil {
		return nil, fmt.Errorf("committing bpf pins: %w", err)
	}

	return obj.SockUDPDestroy, nil
}
