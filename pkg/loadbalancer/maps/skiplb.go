// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package maps

import (
	"errors"
	"fmt"
	"iter"
	"net/netip"

	"github.com/cilium/hive/cell"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/byteorder"
	mapregistry "github.com/cilium/cilium/pkg/maps/registry"
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

func NewSkipLBMap(lifecycle cell.Lifecycle, reg *mapregistry.MapRegistry) SkipLBMap {
	skipLBMap := &skipLBMap{mapRegistry: reg}

	lifecycle.Append(cell.Hook{OnStart: skipLBMap.start, OnStop: skipLBMap.stop})

	return skipLBMap
}

func openOrCreate(m *bpf.Map) error {
	if testutils.IsPrivileged() {
		// Running in privileged tests, don't pin the map.
		return m.CreateUnpinned()
	}
	return m.OpenOrCreate()
}

func (m *skipLBMap) start(cell.HookContext) (err error) {
	if option.Config.EnableIPv4 {
		if m.bpfMap4, err = bpf.NewMapFromRegistry(m.mapRegistry, SkipLB4MapName,
			&SkipLB4Key{}, &SkipLB4Value{}); err != nil {
			return fmt.Errorf("pull %s map from registry: %w", SkipLB4MapName, err)
		}
		if err = openOrCreate(m.bpfMap4); err != nil {
			return fmt.Errorf("failed to open or create %s: %w", SkipLB4MapName, err)
		}
	}
	if option.Config.EnableIPv6 {
		if m.bpfMap6, err = bpf.NewMapFromRegistry(m.mapRegistry, SkipLB6MapName,
			&SkipLB6Key{}, &SkipLB6Value{}); err != nil {
			return fmt.Errorf("pull %s map from registry: %w", SkipLB6MapName, err)
		}
		if err = openOrCreate(m.bpfMap6); err != nil {
			return fmt.Errorf("failed to open or create %s: %w", SkipLB6MapName, err)
		}
	}
	return nil
}

func (m *skipLBMap) stop(cell.HookContext) (err error) {
	if m.bpfMap4 != nil {
		err = errors.Join(err, m.bpfMap4.Close())
	}
	if m.bpfMap6 != nil {
		err = errors.Join(err, m.bpfMap6.Close())
	}
	return
}

func (m *skipLBMap) AllLB4() iter.Seq2[*SkipLB4Key, *SkipLB4Value] {
	return func(yield func(*SkipLB4Key, *SkipLB4Value) bool) {
		var keys []*SkipLB4Key
		var values []*SkipLB4Value
		_ = dumpMap(m.bpfMap4, func(k *SkipLB4Key, v *SkipLB4Value) {
			k.Port = byteorder.NetworkToHost16(k.Port)
			keys = append(keys, k)
			values = append(values, v)
		})
		for i := range keys {
			if !yield(keys[i], values[i]) {
				return
			}
		}
	}
}

func (m *skipLBMap) AllLB6() iter.Seq2[*SkipLB6Key, *SkipLB6Value] {
	return func(yield func(*SkipLB6Key, *SkipLB6Value) bool) {
		var keys []*SkipLB6Key
		var values []*SkipLB6Value
		_ = dumpMap(m.bpfMap6, func(k *SkipLB6Key, v *SkipLB6Value) {
			k.Port = byteorder.NetworkToHost16(k.Port)
			keys = append(keys, k)
			values = append(values, v)
		})
		for i := range keys {
			if !yield(keys[i], values[i]) {
				return
			}
		}
	}
}

// AddLB4 adds the given tuple to skip LB for to the BPF v4 map.
func (m *skipLBMap) AddLB4(netnsCookie uint64, ip netip.Addr, port uint16) error {
	return m.bpfMap4.Update(
		NewSkipLB4Key(netnsCookie, ip, port),
		&SkipLB4Value{})
}

// AddLB6 adds the given tuple to skip LB for to the BPF v6 map.
func (m *skipLBMap) AddLB6(netnsCookie uint64, ip netip.Addr, port uint16) error {
	return m.bpfMap6.Update(
		NewSkipLB6Key(netnsCookie, ip, port),
		&SkipLB6Value{})
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
	mapRegistry *mapregistry.MapRegistry
	bpfMap4     *bpf.Map
	bpfMap6     *bpf.Map
}
