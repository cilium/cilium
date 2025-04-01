// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package loader

import (
	"fmt"
	"log/slog"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/maps/lbmap"
	"github.com/cilium/cilium/pkg/maps/socktermfilter"

	"github.com/cilium/ebpf"
)

var (
	BPFSockTermPath = "/bpf/bpf_sock_term.o"
)

type sockTermObjects struct {
	SockUDPDestroy *ebpf.Program `ebpf:"cil_sock_udp_destroy"`
	SockTermFilter *ebpf.Map     `ebpf:"cilium_sock_term_filter"`
}

// LoadSockTerm configures and loads the cil_sock_udp_destroy program and
// cilium_sock_term_filter map. mapPinPath specifies the pin path for the
// cilium_lb4_reverse_sk and cilium_lb4_reverse_sk maps. If mapPinPath is empty,
// it uses the default pin path.
func LoadSockTerm(l *slog.Logger, mapPinPath string) (*ebpf.Program, *socktermfilter.Map, error) {
	spec, err := bpf.LoadCollectionSpec(l, BPFSockTermPath)
	if err != nil {
		return nil, nil, fmt.Errorf("load eBPF ELF: %w", err)
	}

	// Since we don't compile bpf_sock_term.o at runtime, we need to adjust
	// MaxEntries for both maps to match the sizes defined in bpf_sock.c.
	if m := spec.Maps[lbmap.SockRevNat4MapName]; m == nil {
		return nil, nil, fmt.Errorf("%s map not found in spec", lbmap.SockRevNat4MapName)
	} else {
		m.MaxEntries = uint32(lbmap.MaxSockRevNat4MapEntries)
	}

	if m := spec.Maps[lbmap.SockRevNat6MapName]; m == nil {
		return nil, nil, fmt.Errorf("%s map not found in spec", lbmap.SockRevNat6MapName)
	} else {
		m.MaxEntries = uint32(lbmap.MaxSockRevNat6MapEntries)
	}

	if mapPinPath == "" {
		mapPinPath = bpf.TCGlobalsPath()
	}

	var obj sockTermObjects
	commit, err := bpf.LoadAndAssign(l, &obj, spec, &bpf.CollectionOptions{
		CollectionOptions: ebpf.CollectionOptions{
			Maps: ebpf.MapOptions{PinPath: mapPinPath},
		},
	})

	if err != nil {
		return nil, nil, fmt.Errorf("loading program: %w", err)
	}

	if err := commit(); err != nil {
		return nil, nil, fmt.Errorf("committing bpf pins: %w", err)
	}

	return obj.SockUDPDestroy, &socktermfilter.Map{
		Map: obj.SockTermFilter,
	}, nil
}
