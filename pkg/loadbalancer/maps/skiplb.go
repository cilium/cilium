// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package maps

import (
	"errors"
	"fmt"
	"iter"
	"log/slog"
	"net"
	"os"

	"github.com/cilium/ebpf"
	"github.com/cilium/hive/cell"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/byteorder"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/maps/registry"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/testutils"
)

// SkipLBMap provides access to the eBPF map that stores entries for which load-balancing is skipped.
type SkipLBMap interface {
	AddLB4(netnsCookie uint64, ip net.IP, port uint16) error
	AddLB6(netnsCookie uint64, ip net.IP, port uint16) error
	DeleteLB4ByAddrPort(ip net.IP, port uint16)
	DeleteLB6ByAddrPort(ip net.IP, port uint16)
	DeleteLB4ByNetnsCookie(cookie uint64)
	DeleteLB6ByNetnsCookie(cookie uint64)
	AllLB4() iter.Seq2[*SkipLB4Key, *SkipLB4Value]
	AllLB6() iter.Seq2[*SkipLB6Key, *SkipLB6Value]
	DeleteLB4(key *SkipLB4Key) error
	DeleteLB6(key *SkipLB6Key) error
	OpenOrCreate() error
	Close() error
}

func newSkipLBMap(lifecycle cell.Lifecycle, logger *slog.Logger, specRegistry *registry.MapSpecRegistry) (out bpf.MapOut[SkipLBMap], err error) {
	skipLBMap := &skipLBMap{logger: logger}

	pinning := ebpf.PinByName
	if testutils.IsPrivileged() {
		// Running in privileged tests, don't pin the map.
		pinning = ebpf.PinNone
	}

	err = specRegistry.ModifyMapSpec(SkipLB4MapName, func(spec *ebpf.MapSpec) error {
		spec.Pinning = pinning
		return nil
	})
	if err != nil {
		return
	}

	err = specRegistry.ModifyMapSpec(SkipLB6MapName, func(spec *ebpf.MapSpec) error {
		spec.Pinning = pinning
		return nil
	})
	if err != nil {
		return
	}

	out = bpf.NewMapOut[SkipLBMap](skipLBMap)

	if os.Getuid() != 0 {
		return
	}

	lifecycle.Append(cell.Hook{
		OnStart: func(cell.HookContext) error {
			if option.Config.EnableIPv4 {
				spec, err := specRegistry.Get(SkipLB4MapName)
				if err != nil {
					return fmt.Errorf("failed to get map spec for %s: %w", SkipLB4MapName, err)
				}

				skipLBMap.bpfMap4 = bpf.NewMap(spec, &SkipLB4Key{}, &SkipLB4Value{})
			}
			if option.Config.EnableIPv6 {
				spec, err := specRegistry.Get(SkipLB6MapName)
				if err != nil {
					return fmt.Errorf("failed to get map spec for %s: %w", SkipLB6MapName, err)
				}

				skipLBMap.bpfMap6 = bpf.NewMap(spec, &SkipLB6Key{}, &SkipLB6Value{})
			}

			return skipLBMap.OpenOrCreate()
		},
		OnStop: func(cell.HookContext) error {
			return skipLBMap.Close()
		},
	})

	return
}

func (m *skipLBMap) OpenOrCreate() error {
	if m.bpfMap4 != nil {
		if err := m.bpfMap4.OpenOrCreate(); err != nil {
			return fmt.Errorf("failed to open or create %s: %w", SkipLB4MapName, err)
		}
	}
	if m.bpfMap6 != nil {
		if err := m.bpfMap6.OpenOrCreate(); err != nil {
			return fmt.Errorf("failed to open or create %s: %w", SkipLB6MapName, err)
		}
	}
	return nil
}

func (m *skipLBMap) Close() (err error) {
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
		if m.bpfMap4 == nil {
			return
		}
		stop := false
		m.bpfMap4.DumpWithCallback(func(k bpf.MapKey, v bpf.MapValue) {
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
		m.bpfMap6.DumpWithCallback(func(k bpf.MapKey, v bpf.MapValue) {
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
func (m *skipLBMap) AddLB4(netnsCookie uint64, ip net.IP, port uint16) error {
	return m.bpfMap4.Update(
		NewSkipLB4Key(netnsCookie, ip.To4(), port),
		&SkipLB4Value{})
}

// AddLB6 adds the given tuple to skip LB for to the BPF v6 map.
func (m *skipLBMap) AddLB6(netnsCookie uint64, ip net.IP, port uint16) error {
	return m.bpfMap6.Update(
		NewSkipLB6Key(netnsCookie, ip.To16(), port),
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

// DeleteLB4ByAddrPort deletes entries associated with the passed address and port from the v4 map.
func (m *skipLBMap) DeleteLB4ByAddrPort(ip net.IP, port uint16) {
	deleted := 0
	errors := 0
	deleteEntry := func(key *SkipLB4Key, _ *SkipLB4Value) {
		if key == nil {
			return
		}
		if ip.To4().Equal(key.Address.IP()) && byteorder.NetworkToHost16(key.Port) == port {
			if err := m.bpfMap4.Delete(key); err != nil {
				errors++
				m.logger.Error(
					"error deleting entry from map",
					logfields.Error, err,
					logfields.Key, key,
					logfields.BPFMapName, SkipLB4MapName,
				)
				return
			}
			deleted++
		}
	}
	if err := m.bpfMap4.DumpWithCallback(func(k bpf.MapKey, v bpf.MapValue) {
		key := k.(*SkipLB4Key)
		value := v.(*SkipLB4Value)
		deleteEntry(key, value)
	}); err != nil {
		m.logger.Error("error iterating over skip_lb4 map", logfields.Error, err)
	}
	m.logger.Info(
		"DeleteLB4ByAddrPort",
		logfields.Address, ip,
		logfields.Port, port,
		logfields.Deleted, deleted,
		logfields.Errors, errors,
	)
}

// DeleteLB4ByNetnsCookie deletes entries associated with the passed netns cookie from the v4 map.
func (m *skipLBMap) DeleteLB4ByNetnsCookie(cookie uint64) {
	deleted := 0
	errors := 0
	deleteEntry := func(key *SkipLB4Key, _ *SkipLB4Value) {
		if key == nil {
			return
		}
		if key.NetnsCookie == cookie {
			if err := m.bpfMap4.Delete(key); err != nil {
				errors++
				m.logger.Error(
					"error deleting entry from map",
					logfields.Key, key,
					logfields.BPFMapName, SkipLB4MapName,
				)
				return
			}
			deleted++
		}
	}
	if err := m.bpfMap4.DumpWithCallback(func(k bpf.MapKey, v bpf.MapValue) {
		key := k.(*SkipLB4Key)
		value := v.(*SkipLB4Value)
		deleteEntry(key, value)
	}); err != nil {
		m.logger.Error("error iterating over skip_lb4 map", logfields.Error, err)
	}
	m.logger.Info(
		"DeleteLB4ByNetnsCookie",
		logfields.Deleted, deleted,
		logfields.Errors, errors,
		logfields.NetnsCookie, cookie,
	)
}

// DeleteLB6ByAddrPort deletes entries associated with the passed address and port from the v6 map.
func (m *skipLBMap) DeleteLB6ByAddrPort(ip net.IP, port uint16) {
	deleted := 0
	errors := 0
	deleteEntry := func(key *SkipLB6Key, _ *SkipLB6Value) {
		if key == nil {
			return
		}
		if ip.To16().Equal(key.Address.IP()) && byteorder.NetworkToHost16(key.Port) == port {
			if err := m.bpfMap6.Delete(key); err != nil {
				errors++
				m.logger.Error(
					"error deleting entry from map",
					logfields.Key, key,
					logfields.BPFMapName, SkipLB6MapName,
				)
				return
			}
			deleted++
		}
	}
	if err := m.bpfMap6.DumpWithCallback(func(k bpf.MapKey, v bpf.MapValue) {
		key := k.(*SkipLB6Key)
		value := v.(*SkipLB6Value)
		deleteEntry(key, value)
	}); err != nil {
		m.logger.Error("error iterating over skip_lb6 map", logfields.Error, err)
	}
	m.logger.Info(
		"DeleteLB6ByAddrPort",
		logfields.Deleted, deleted,
		logfields.Errors, errors,
		logfields.Address, ip,
		logfields.Port, port,
	)
}

// DeleteLB6ByNetnsCookie deletes entries associated with the passed netns cookie from the v6 map.
func (m *skipLBMap) DeleteLB6ByNetnsCookie(cookie uint64) {
	deleted := 0
	errors := 0
	deleteEntry := func(key *SkipLB6Key, _ *SkipLB6Value) {
		if key == nil {
			return
		}
		if key.NetnsCookie == cookie {
			if err := m.bpfMap6.Delete(key); err != nil {
				errors++
				m.logger.Error(
					"error deleting entry from map",
					logfields.Error, err,
					logfields.Key, key,
					logfields.BPFMapName, SkipLB6MapName,
				)
				return
			}
			deleted++
		}
	}
	if err := m.bpfMap6.DumpWithCallback(func(k bpf.MapKey, v bpf.MapValue) {
		key := k.(*SkipLB6Key)
		value := v.(*SkipLB6Value)
		deleteEntry(key, value)
	}); err != nil {
		m.logger.Error("error iterating over skip_lb6 map", logfields.Error, err)
	}
	m.logger.Info(
		"DeleteLB6ByNetnsCookie",
		logfields.Deleted, deleted,
		logfields.Errors, errors,
		logfields.NetnsCookie, cookie,
	)
}

type skipLBMap struct {
	logger  *slog.Logger
	bpfMap4 *bpf.Map
	bpfMap6 *bpf.Map
}
