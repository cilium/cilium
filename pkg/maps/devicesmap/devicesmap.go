// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package devicesmap

import (
	"log/slog"
	"net"
	"unsafe"

	"github.com/cilium/hive/cell"
	"golang.org/x/sys/unix"

	"github.com/cilium/cilium/pkg/ebpf"
	"github.com/cilium/cilium/pkg/types"
)

var Cell = cell.Provide(NewMap)

type Map interface {
	Upsert(ifindex uint32, state DeviceState) error
	Delete(ifindex uint32) error
	Lookup(ifindex uint32) (*DeviceState, error)
	IterateWithCallback(cb IterateCallback) error
}

type devicesMap struct {
	*ebpf.Map
}

const mapName = "cilium_devices"

func NewMap(lifecycle cell.Lifecycle, logger *slog.Logger) Map {
	dm := &devicesMap{}

	lifecycle.Append(cell.Hook{
		OnStart: func(hc cell.HookContext) error {
			m, err := ebpf.LoadRegisterMap(logger, mapName)
			if err != nil {
				m = ebpf.NewMap(logger, &ebpf.MapSpec{
					Name:       mapName,
					Type:       ebpf.Hash,
					KeySize:    uint32(unsafe.Sizeof(DeviceKey{})),
					ValueSize:  uint32(unsafe.Sizeof(DeviceState{})),
					MaxEntries: 256,
					Flags:      unix.BPF_F_NO_PREALLOC,
					Pinning:    ebpf.PinByName,
				})
				if err := m.OpenOrCreate(); err != nil {
					return err
				}
			}

			dm.Map = m
			return nil
		},
	})

	return dm
}

func (m *devicesMap) Upsert(ifindex uint32, state DeviceState) error {
	key := DeviceKey{IfIndex: ifindex}
	return m.Map.Put(key, state)
}

func (m *devicesMap) Delete(ifindex uint32) error {
	key := DeviceKey{IfIndex: ifindex}
	return m.Map.Delete(key)
}

func (m *devicesMap) Lookup(ifindex uint32) (*DeviceState, error) {
	key := DeviceKey{IfIndex: ifindex}
	state := DeviceState{}
	if err := m.Map.Lookup(&key, &state); err != nil {
		return nil, err
	}
	return &state, nil
}

// IterateCallback represents the signature of the callback used for iteration.
type IterateCallback func(*DeviceKey, *DeviceState)

func (m *devicesMap) IterateWithCallback(cb IterateCallback) error {
	return m.Map.IterateWithCallback(&DeviceKey{}, &DeviceState{},
		func(k, v any) {
			cb(k.(*DeviceKey), v.(*DeviceState))
		},
	)
}

// DeviceKey matches the BPF map key (__u32 ifindex).
type DeviceKey struct {
	IfIndex uint32 `align:"ifindex"`
}

// DeviceState matches struct device_state in bpf/lib/devices.h.
type DeviceState struct {
	MAC types.MACAddr `align:"mac"`
	_   uint16
	L3  uint8  `align:"l3"`
	_   uint8  `align:"pad1"`
	_   uint16 `align:"pad2"`
	_   uint32 `align:"pad3"`
}

func NewDeviceState(mac net.HardwareAddr) DeviceState {
	state := DeviceState{}
	if len(mac) == len(state.MAC) {
		copy(state.MAC[:], mac)
	}
	if len(mac) != 6 {
		state.L3 = 1
	}
	return state
}
