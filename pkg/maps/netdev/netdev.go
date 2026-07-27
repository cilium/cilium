// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package netdev

import (
	"fmt"
	"net"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/ebpf"
	"github.com/cilium/cilium/pkg/types"
)

// Map provides access to the eBPF map cilium_devices.
type Map interface {
	Upsert(ifindex uint32, state DeviceState) error

	Lookup(ifindex uint32) (*DeviceState, error)

	IterateWithCallback(cb IterateCallback) error

	Delete(ifindex uint32) error
}

type netDevMap struct {
	*bpf.Map
}

func newNetDevMap() *netDevMap {
	var index Index
	return &netDevMap{
		Map: bpf.NewMap(
			"cilium_devices",
			ebpf.Hash,
			&index,
			&DeviceState{},
			512,
			0,
		),
	}
}

func (m *netDevMap) Upsert(ifindex uint32, state DeviceState) error {
	key := Index(ifindex)
	return m.Map.Update(&key, &state)
}

func (m *netDevMap) Lookup(ifindex uint32) (*DeviceState, error) {
	key := Index(ifindex)
	state, err := m.Map.Lookup(&key)
	if err != nil {
		return nil, err
	}
	return state.(*DeviceState), nil
}

// IterateCallback represents the signature of the callback used for iteration.
type IterateCallback func(*Index, *DeviceState)

func (m *netDevMap) IterateWithCallback(cb IterateCallback) error {
	return m.Map.DumpWithCallback(func(k bpf.MapKey, v bpf.MapValue) {
		cb(k.(*Index), v.(*DeviceState))
	})
}

// Delete removes an entry from the map.
func (m *netDevMap) Delete(ifindex uint32) error {
	key := Index(ifindex)
	return m.Map.Delete(&key)
}

func (m *netDevMap) init() error {
	if err := m.Map.OpenOrCreate(); err != nil {
		return fmt.Errorf("failed to init bpf map: %w", err)
	}
	return nil
}

func (m *netDevMap) close() error {
	if err := m.Map.Close(); err != nil {
		return fmt.Errorf("failed to close bpf map: %w", err)
	}
	return nil
}

// Index matches the BPF map key (__u32 ifindex).
type Index uint32

func (k *Index) New() bpf.MapKey {
	return new(Index)
}

func (k *Index) String() string {
	return fmt.Sprintf("%d", uint32(*k))
}

// DeviceState matches struct device_state in bpf/lib/network_device.h.
type DeviceState struct {
	MAC types.MACAddr `align:"mac"`
	_   uint16
	L3  DeviceStateL3 `align:"l3"`
	_   uint8         `align:"pad1"`
	_   uint16        `align:"pad2"`
	_   uint32        `align:"pad3"`
}

func NewDeviceState(mac net.HardwareAddr) DeviceState {
	state := DeviceState{}
	if len(mac) == len(state.MAC) {
		copy(state.MAC[:], mac)
	} else {
		state.L3 |= deviceStateL3Mask
	}
	return state
}

// DeviceStateL3 represents device L3 states.
type DeviceStateL3 uint8

const deviceStateL3Mask DeviceStateL3 = 1 << iota

func (s *DeviceState) New() bpf.MapValue {
	return &DeviceState{}
}

func (s *DeviceState) String() string {
	return fmt.Sprintf("%s %b", s.MAC.String(), s.L3)
}
