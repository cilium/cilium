// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package devicemap

import (
	"fmt"
	"log/slog"
	"unsafe"

	"golang.org/x/sys/unix"

	"github.com/cilium/cilium/pkg/ebpf"
	"github.com/cilium/cilium/pkg/mac"
)

const (
	MapName    = "cilium_device_map"
	MaxEntries = 256
)

// Map provides access to the eBPF map node.
type Map interface {
	// Lookup returns the device map object associated with the provided
	// ifIndex.
	Lookup(ifIndex uint32) (DeviceValue, error)

	// Update inserts or updates the device map object associated with the provided
	// ifIndex, mac and l3.
	Update(ifIndex uint32, mac mac.Uint64MAC, l3 uint8) error

	// Delete deletes the device map object associated with the provided
	// ifIndex.
	Delete(ifIndex uint32) error

	// IterateWithCallback iterates through all the keys/values of a device map,
	// passing each key/value pair to the cb callback.
	IterateWithCallback(cb DeviceIterateCallback) error
}

type deviceMap struct {
	bpfMap *ebpf.Map
}

func newMap(logger *slog.Logger) *deviceMap {
	return &deviceMap{
		bpfMap: ebpf.NewMap(logger, &ebpf.MapSpec{
			Name:       MapName,
			Type:       ebpf.Hash,
			KeySize:    uint32(unsafe.Sizeof(DeviceKey{})),
			ValueSize:  uint32(unsafe.Sizeof(DeviceValue{})),
			MaxEntries: uint32(MaxEntries),
			Flags:      unix.BPF_F_NO_PREALLOC,
			Pinning:    ebpf.PinByName,
		}),
	}
}

type DeviceKey struct {
	IfIndex uint32 `align:"ifindex"`
}

type DeviceValue struct {
	MAC mac.Uint64MAC `align:"mac"`
	L3  uint8         `align:"l3"`
	Pad [7]uint8      `align:"pad"`
}

func (m *deviceMap) Lookup(ifIndex uint32) (DeviceValue, error) {
	key := DeviceKey{IfIndex: ifIndex}
	val := DeviceValue{}
	err := m.bpfMap.Lookup(key, &val)
	return val, err
}

func (m *deviceMap) Update(ifIndex uint32, mac mac.Uint64MAC, l3 uint8) error {
	key := DeviceKey{IfIndex: ifIndex}
	val := DeviceValue{L3: l3, MAC: mac}
	return m.bpfMap.Update(key, val, 0)
}

func (m *deviceMap) Delete(ifIndex uint32) error {
	key := DeviceKey{IfIndex: ifIndex}
	return m.bpfMap.Map.Delete(key)
}

// DeviceIterateCallback represents the signature of the callback function
// expected by the IterateWithCallback method, which in turn is used to iterate
// all the keys/values of a device map.
type DeviceIterateCallback func(*DeviceKey, *DeviceValue)

func (m *deviceMap) IterateWithCallback(cb DeviceIterateCallback) error {
	return m.bpfMap.IterateWithCallback(&DeviceKey{}, &DeviceValue{},
		func(k, v any) {
			key := k.(*DeviceKey)
			value := v.(*DeviceValue)

			cb(key, value)
		})
}

// LoadDeviceMap loads the pre-initialized device map for access.
// This should only be used from components which aren't capable of using hive - mainly the Cilium CLI.
// It needs to initialized beforehand via the Cilium Agent.
func LoadDeviceMap(logger *slog.Logger) (Map, error) {
	bpfMap, err := ebpf.LoadRegisterMap(logger, MapName)
	if err != nil {
		return nil, fmt.Errorf("failed to load bpf map: %w", err)
	}

	return &deviceMap{bpfMap: bpfMap}, nil
}

func (m *deviceMap) init() error {
	if err := m.bpfMap.OpenOrCreate(); err != nil {
		return fmt.Errorf("failed to init bpf map: %w", err)
	}

	return nil
}

func (m *deviceMap) close() error {
	if err := m.bpfMap.Close(); err != nil {
		return fmt.Errorf("failed to close bpf map: %w", err)
	}

	return nil
}
