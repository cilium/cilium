// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package lbmap

import (
	"errors"
	"fmt"
	"iter"
	"log/slog"
	"net"
	"unsafe"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/byteorder"
	"github.com/cilium/cilium/pkg/ebpf"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/testutils"
	"github.com/cilium/cilium/pkg/types"
)

const (
	// SkipLB4MapName is the name of the IPv4 BPF map that stores entries to skip LB.
	SkipLB4MapName = "cilium_skip_lb4"

	// SkipLB6MapName is the name of the IPv6 BPF map that stores entries to skip LB.
	SkipLB6MapName = "cilium_skip_lb6"

	// SkipLBMapMaxEntries is the maximum number of entries in the skip LB BPF maps.
	SkipLBMapMaxEntries = 100
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
			Flags:      bpf.BPF_F_NO_PREALLOC,
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
			Flags:      bpf.BPF_F_NO_PREALLOC,
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

// SkipLB4Key is the tuple with netns cookie, address and port and used as key in
// the skip LB4 map.
type SkipLB4Key struct {
	NetnsCookie uint64     `align:"netns_cookie"`
	Address     types.IPv4 `align:"address"`
	Port        uint16     `align:"port"`
	Pad         int16      `align:"pad"`
}

type SkipLB4Value struct {
	Pad uint8 `align:"pad"`
}

// NewSkipLB4Key creates the SkipLB4Key
func NewSkipLB4Key(netnsCookie uint64, address net.IP, port uint16) *SkipLB4Key {
	key := SkipLB4Key{
		NetnsCookie: netnsCookie,
		Port:        byteorder.HostToNetwork16(port),
	}
	copy(key.Address[:], address.To4())

	return &key
}

func (k *SkipLB4Key) New() bpf.MapKey { return &SkipLB4Key{} }

// GetValuePtr returns the unsafe pointer to the BPF value
func (v *SkipLB4Value) GetValuePtr() unsafe.Pointer { return unsafe.Pointer(v) }

// String converts the key into a human-readable string format.
func (k *SkipLB4Key) String() string {
	return fmt.Sprintf("[%d]:%d, %d", k.NetnsCookie, k.Address, k.Port)
}

func (v *SkipLB4Value) New() bpf.MapValue { return &SkipLB4Value{} }

// String converts the value into a human-readable string format.
func (v *SkipLB4Value) String() string {
	return ""
}

// SkipLB6Key is the tuple with netns cookie, address and port and used as key in
// the skip LB6 map.
type SkipLB6Key struct {
	NetnsCookie uint64     `align:"netns_cookie"`
	Address     types.IPv6 `align:"address"`
	Pad         uint32     `align:"pad"`
	Port        uint16     `align:"port"`
	Pad2        uint16     `align:"pad2"`
}

type SkipLB6Value struct {
	Pad uint8 `align:"pad"`
}

// NewSkipLB6Key creates the SkipLB6Key
func NewSkipLB6Key(netnsCookie uint64, address net.IP, port uint16) *SkipLB6Key {
	key := SkipLB6Key{
		NetnsCookie: netnsCookie,
		Port:        byteorder.HostToNetwork16(port),
	}
	copy(key.Address[:], address.To16())

	return &key
}

func (k *SkipLB6Key) New() bpf.MapKey { return &SkipLB6Key{} }

// GetKeyPtr returns the unsafe pointer to the BPF key
func (k *SkipLB6Key) GetKeyPtr() unsafe.Pointer { return unsafe.Pointer(k) }

// GetValuePtr returns the unsafe pointer to the BPF value
func (v *SkipLB6Value) GetValuePtr() unsafe.Pointer { return unsafe.Pointer(v) }

// String converts the key into a human-readable string format.
func (k *SkipLB6Key) String() string {
	return fmt.Sprintf("[%d]:%d, %d", k.NetnsCookie, k.Address, k.Port)
}

func (v *SkipLB6Value) New() bpf.MapValue { return &SkipLB6Value{} }

// String converts the value into a human-readable string format.
func (v *SkipLB6Value) String() string {
	return ""
}

// NewValue returns a new empty instance of the structure representing the BPF
// map value
func (k *SkipLB6Key) NewValue() bpf.MapValue { return &SkipLB6Value{} }

type skipLBMap struct {
	logger  *slog.Logger
	bpfMap4 *ebpf.Map
	bpfMap6 *ebpf.Map
}
