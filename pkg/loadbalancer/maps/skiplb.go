// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package maps

import (
	"errors"
	"fmt"
	"iter"
	"log/slog"
	"net/netip"

	"github.com/cilium/hive/cell"

	"github.com/cilium/cilium/pkg/byteorder"
	"github.com/cilium/cilium/pkg/ebpf"
	"github.com/cilium/cilium/pkg/maps/registry"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/testutils"
)

// SkipLBMap provides access to the eBPF map that stores entries for which load-balancing is skipped.
type SkipLBMap interface {
	AddLB4(netnsCookie uint64, ip netip.Addr, port uint16) error
	AddLB6(netnsCookie uint64, ip netip.Addr, port uint16) error
	AllLB4() iter.Seq2[*SkipLB4Key, *SkipLB4Value]
	AllLB6() iter.Seq2[*SkipLB6Key, *SkipLB6Value]
	DeleteLB4(key *SkipLB4Key) error
	DeleteLB6(key *SkipLB6Key) error
}

// ManagedSkipLBMap is a SkipLBMap with Hive lifecycle hooks. The maps are
// created from the specs in the map registry when the lifecycle starts and
// closed when it stops.
type ManagedSkipLBMap interface {
	SkipLBMap
	cell.HookInterface
}

func NewSkipLBMap(logger *slog.Logger, reg *registry.MapRegistry) ManagedSkipLBMap {
	return &skipLBMap{logger: logger, reg: reg}
}

// Start implements cell.HookInterface.
func (m *skipLBMap) Start(cell.HookContext) error {
	pinning := ebpf.PinByName
	if testutils.IsPrivileged() {
		// Running in privileged tests, don't pin the map.
		pinning = ebpf.PinNone
	}

	if option.Config.EnableIPv4 {
		spec, err := m.reg.Get(SkipLB4MapName)
		if err != nil {
			return fmt.Errorf("getting %s map spec: %w", SkipLB4MapName, err)
		}
		spec.Pinning = pinning
		m.bpfMap4 = ebpf.NewMap(m.logger, spec)
		if err := m.bpfMap4.OpenOrCreate(); err != nil {
			return fmt.Errorf("open or create %s: %w", SkipLB4MapName, err)
		}
	}
	if option.Config.EnableIPv6 {
		spec, err := m.reg.Get(SkipLB6MapName)
		if err != nil {
			return fmt.Errorf("getting %s map spec: %w", SkipLB6MapName, err)
		}
		spec.Pinning = pinning
		m.bpfMap6 = ebpf.NewMap(m.logger, spec)
		if err := m.bpfMap6.OpenOrCreate(); err != nil {
			return fmt.Errorf("open or create %s: %w", SkipLB6MapName, err)
		}
	}

	return nil
}

// Stop implements cell.HookInterface.
func (m *skipLBMap) Stop(cell.HookContext) error {
	return errors.Join(closeMap(m.bpfMap4), closeMap(m.bpfMap6))
}

func closeMap(m *ebpf.Map) error {
	if m == nil {
		return nil
	}
	return m.Close()
}

func (m *skipLBMap) AllLB4() iter.Seq2[*SkipLB4Key, *SkipLB4Value] {
	return func(yield func(*SkipLB4Key, *SkipLB4Value) bool) {
		if m.bpfMap4 == nil {
			return
		}
		stop := false
		m.bpfMap4.IterateWithCallback(&SkipLB4Key{}, &SkipLB4Value{},
			func(k, v any) {
				key := k.(*SkipLB4Key)
				value := v.(*SkipLB4Value)
				key.Port = byteorder.NetworkToHost16(key.Port)
				if !stop && !yield(key, value) {
					stop = true
				}
			})
	}
}

func (m *skipLBMap) AllLB6() iter.Seq2[*SkipLB6Key, *SkipLB6Value] {
	return func(yield func(*SkipLB6Key, *SkipLB6Value) bool) {
		if m.bpfMap6 == nil {
			return
		}
		stop := false
		m.bpfMap6.IterateWithCallback(&SkipLB6Key{}, &SkipLB6Value{},
			func(k, v any) {
				key := k.(*SkipLB6Key)
				value := v.(*SkipLB6Value)
				key.Port = byteorder.NetworkToHost16(key.Port)
				if !stop && !yield(key, value) {
					stop = true
				}
			})
	}
}

// AddLB4 adds the given tuple to skip LB for to the BPF v4 map.
func (m *skipLBMap) AddLB4(netnsCookie uint64, ip netip.Addr, port uint16) error {
	return m.bpfMap4.Update(
		NewSkipLB4Key(netnsCookie, ip, port),
		&SkipLB4Value{}, 0)
}

// AddLB6 adds the given tuple to skip LB for to the BPF v6 map.
func (m *skipLBMap) AddLB6(netnsCookie uint64, ip netip.Addr, port uint16) error {
	return m.bpfMap6.Update(
		NewSkipLB6Key(netnsCookie, ip, port),
		&SkipLB6Value{}, 0)
}

func (m *skipLBMap) DeleteLB4(key *SkipLB4Key) error {
	key.Port = byteorder.HostToNetwork16(key.Port)
	return m.bpfMap4.Delete(key)
}

func (m *skipLBMap) DeleteLB6(key *SkipLB6Key) error {
	key.Port = byteorder.HostToNetwork16(key.Port)
	return m.bpfMap6.Delete(key)
}

type skipLBMap struct {
	logger  *slog.Logger
	reg     *registry.MapRegistry
	bpfMap4 *ebpf.Map
	bpfMap6 *ebpf.Map
}
