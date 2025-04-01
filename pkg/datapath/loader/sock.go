// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package loader

import (
	"fmt"
	"log/slog"
	"net"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/byteorder"
	"github.com/cilium/cilium/pkg/loadbalancer/maps"

	"github.com/cilium/ebpf"
)

const (
	v4ProgName    = "cil_sock_udp_destroy_v4"
	v6ProgName    = "cil_sock_udp_destroy_v6"
	filterVarName = "cilium_sock_term_filter"
)

type FilterSetter func(af uint8, addr net.IP, port uint16) error

// LoadSockTerm loads the cil_sock_udp_destroy_v4 and cil_sock_udp_destroy_v6
// programs. It returns a handle to the programs and a function that sets the
// socket filter.
func LoadSockTerm(l *slog.Logger, sockRevNat4, sockRevNat6 *bpf.Map) (*ebpf.Program, *ebpf.Program, FilterSetter, error) {
	spec, err := loadSock_term()
	if err != nil {
		return nil, nil, nil, fmt.Errorf("load eBPF ELF: %w", err)
	}

	mapReplacements := make(map[string]*bpf.Map)

	if m := spec.Maps[maps.SockRevNat4MapName]; m == nil {
		return nil, nil, nil, fmt.Errorf("%s map not found in spec", maps.SockRevNat4MapName)
	} else if sockRevNat4 == nil {
		delete(spec.Maps, maps.SockRevNat4MapName)
		delete(spec.Programs, v4ProgName)
	} else {
		m.Flags = sockRevNat4.Flags()
		m.MaxEntries = sockRevNat4.MaxEntries()
		mapReplacements[maps.SockRevNat4MapName] = sockRevNat4
	}

	if m := spec.Maps[maps.SockRevNat6MapName]; m == nil {
		return nil, nil, nil, fmt.Errorf("%s map not found in spec", maps.SockRevNat6MapName)
	} else if sockRevNat6 == nil {
		delete(spec.Maps, maps.SockRevNat6MapName)
		delete(spec.Programs, v6ProgName)
	} else {
		m.Flags = sockRevNat6.Flags()
		m.MaxEntries = sockRevNat6.MaxEntries()
		mapReplacements[maps.SockRevNat6MapName] = sockRevNat6
	}

	// We can't assign directly to a sock_termObjects, since some maps and
	// programs may be missing.
	coll, commit, err := bpf.LoadCollection(l, spec, &bpf.CollectionOptions{
		CollectionOptions: ebpf.CollectionOptions{
			Maps: ebpf.MapOptions{PinPath: bpf.TCGlobalsPath()},
		},
		MapReplacements: mapReplacements,
	})

	if err != nil {
		return nil, nil, nil, fmt.Errorf("loading collection: %w", err)
	}

	if err := commit(); err != nil {
		return nil, nil, nil, fmt.Errorf("committing bpf pins: %w", err)
	}

	return coll.Programs[v4ProgName], coll.Programs[v6ProgName], func(af uint8, addr net.IP, port uint16) error {
		var value sock_termSockTermFilter
		value.AddressFamily = af
		value.Port = byteorder.NetworkToHost16(port)
		copy(value.Address.Addr6.Addr[:], addr.To16())

		return coll.Variables[filterVarName].Set(&value)
	}, nil
}
