// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package maps

import (
	"errors"
	"fmt"
	"iter"
	"log/slog"
	"net"
	"unsafe"

	"golang.org/x/sys/unix"

	"github.com/cilium/cilium/pkg/byteorder"
	"github.com/cilium/cilium/pkg/ebpf"
	"github.com/cilium/cilium/pkg/logging/logfields"
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

func NewSkipLBMap(logger *slog.Logger) (SkipLBMap, error) {
	skipLBMap := &skipLBMap{logger: logger}

	pinning := ebpf.PinByName
	if testutils.IsPrivileged() {
		// Running in privileged tests, don't pin the map.
		pinning = ebpf.PinNone
	}

	if option.Config.EnableIPv4 {
		skipLBMap.bpfMap4 = ebpf.NewMap(logger, &ebpf.MapSpec{
			Name:       SkipLB4MapName,
			Type:       ebpf.Hash,
			KeySize:    uint32(unsafe.Sizeof(SkipLB4Key{})),
			ValueSize:  uint32(unsafe.Sizeof(SkipLB4Value{})),
			MaxEntries: SkipLBMapMaxEntries,
			Flags:      unix.BPF_F_NO_PREALLOC,
			Pinning:    pinning,
		})
	}
	if option.Config.EnableIPv6 {
		skipLBMap.bpfMap6 = ebpf.NewMap(logger, &ebpf.MapSpec{
			Name:       SkipLB6MapName,
			Type:       ebpf.Hash,
			KeySize:    uint32(unsafe.Sizeof(SkipLB6Key{})),
			ValueSize:  uint32(unsafe.Sizeof(SkipLB6Value{})),
			MaxEntries: SkipLBMapMaxEntries,
			Flags:      unix.BPF_F_NO_PREALLOC,
			Pinning:    pinning,
		})
	}

	return skipLBMap, nil
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
func (m *skipLBMap) AddLB4(netnsCookie uint64, ip net.IP, port uint16) error {
	return m.bpfMap4.Update(
		NewSkipLB4Key(netnsCookie, ip.To4(), port),
		&SkipLB4Value{}, 0)
}

// AddLB6 adds the given tuple to skip LB for to the BPF v6 map.
func (m *skipLBMap) AddLB6(netnsCookie uint64, ip net.IP, port uint16) error {
	return m.bpfMap6.Update(
		NewSkipLB6Key(netnsCookie, ip.To16(), port),
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
	if err := m.bpfMap4.IterateWithCallback(&SkipLB4Key{}, &SkipLB4Value{},
		func(k, v any) {
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
	if err := m.bpfMap4.IterateWithCallback(&SkipLB4Key{}, &SkipLB4Value{},
		func(k, v any) {
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
	if err := m.bpfMap6.IterateWithCallback(&SkipLB6Key{}, &SkipLB6Value{},
		func(k, v any) {
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
	if err := m.bpfMap6.IterateWithCallback(&SkipLB6Key{}, &SkipLB6Value{},
		func(k, v any) {
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
	bpfMap4 *ebpf.Map
	bpfMap6 *ebpf.Map
}
