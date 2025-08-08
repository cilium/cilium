// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package loader

import (
	"fmt"
	"log/slog"
	"net"

	"github.com/cilium/cilium/pkg/bpf"
	bpfgen "github.com/cilium/cilium/pkg/datapath/bpf"
	"github.com/cilium/cilium/pkg/loadbalancer/maps"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
)

const (
	v4UDPProgName = "cil_sock_udp_destroy_v4"
	v4TCPProgName = "cil_sock_tcp_destroy_v4"
	v6UDPProgName = "cil_sock_udp_destroy_v6"
	v6TCPProgName = "cil_sock_tcp_destroy_v6"
	filterVarName = "cilium_sock_term_filter"
)

type FilterSetter func(af uint8, addr net.IP, port uint16) error

// LoadSockTerm loads the cil_sock_udp_destroy_v4, cil_sock_tcp_destroy_v4,
// cil_sock_tcp_destroy_v6, and cil_sock_udp_destroy_v6 programs. It returns a
// handle to the programs and a function that sets the socket filter.
func LoadSockTerm(l *slog.Logger, sockRevNat4, sockRevNat6 *bpf.Map) (*bpfgen.SockTermPrograms, FilterSetter, error) {
	spec, err := bpfgen.LoadSockTerm()
	if err != nil {
		return nil, nil, fmt.Errorf("load eBPF ELF: %w", err)
	}

	mapReplacements := make(map[string]*bpf.Map)

	if m := spec.Maps[maps.SockRevNat4MapName]; m == nil {
		return nil, nil, fmt.Errorf("%s map not found in spec", maps.SockRevNat4MapName)
	} else if sockRevNat4 == nil {
		delete(spec.Maps, maps.SockRevNat4MapName)
		delete(spec.Programs, v4UDPProgName)
		delete(spec.Programs, v4TCPProgName)
	} else {
		m.Flags = sockRevNat4.Flags()
		m.MaxEntries = sockRevNat4.MaxEntries()
		mapReplacements[maps.SockRevNat4MapName] = sockRevNat4
	}

	if m := spec.Maps[maps.SockRevNat6MapName]; m == nil {
		return nil, nil, fmt.Errorf("%s map not found in spec", maps.SockRevNat6MapName)
	} else if sockRevNat6 == nil {
		delete(spec.Maps, maps.SockRevNat6MapName)
		delete(spec.Programs, v6UDPProgName)
		delete(spec.Programs, v6TCPProgName)
	} else {
		m.Flags = sockRevNat6.Flags()
		m.MaxEntries = sockRevNat6.MaxEntries()
		mapReplacements[maps.SockRevNat6MapName] = sockRevNat6
	}

	// Since the programs use the bpf_sock_destroy() kfunc, the loader
	// parses and caches BTF from vmlinux on the first go to be reused
	// by subsequent program loads. For now, only bpf_sock_term uses kfuncs,
	// and we only load this at the start, so flush this cache after loading
	// is done to avoid holding onto an extra ~15MB of memory.
	//
	// See GH-37907 for discussion
	defer btf.FlushKernelSpec()

	// We can't assign directly to a sock_termObjects, since some maps and
	// programs may be missing.
	coll, commit, err := bpf.LoadCollection(l, spec, &bpf.CollectionOptions{
		CollectionOptions: ebpf.CollectionOptions{
			Maps: ebpf.MapOptions{PinPath: bpf.TCGlobalsPath()},
		},
		MapReplacements: mapReplacements,
	})

	if err != nil {
		return nil, nil, fmt.Errorf("loading collection: %w", err)
	}

	if err := commit(); err != nil {
		return nil, nil, fmt.Errorf("committing bpf pins: %w", err)
	}

	return &bpfgen.SockTermPrograms{
			CilSockUdpDestroyV4: coll.Programs[v4UDPProgName],
			CilSockTcpDestroyV4: coll.Programs[v4TCPProgName],
			CilSockUdpDestroyV6: coll.Programs[v6UDPProgName],
			CilSockTcpDestroyV6: coll.Programs[v6TCPProgName],
		}, func(af uint8, addr net.IP, port uint16) error {
			var value bpfgen.SockTermSockTermFilter
			value.AddressFamily = af
			value.Port = port
			copy(value.Address.Addr6.Addr[:], addr.To16())

			return coll.Variables[filterVarName].Set(&value)
		}, nil
}
