// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package devicemap

import (
	"fmt"

	"golang.org/x/sys/unix"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/ebpf"
	"github.com/cilium/cilium/pkg/mac"
)

const (
	MapName    = "cilium_device_map"
	MaxEntries = 256
)

type DeviceMap struct {
	*bpf.Map
}

func newMap() *DeviceMap {
	return &DeviceMap{
		bpf.NewMap(
			MapName,
			ebpf.Hash,
			&DeviceKey{},
			&DeviceValue{},
			MaxEntries,
			unix.BPF_F_NO_PREALLOC,
		),
	}
}

type DeviceKey struct {
	IfIndex uint32 `align:"ifindex"`
}

func (k *DeviceKey) String() string {
	return fmt.Sprintf("%d", k.IfIndex)
}

func (k *DeviceKey) New() bpf.MapKey { return &DeviceKey{} }

type DeviceValue struct {
	MAC mac.Uint64MAC `align:"mac"`
	L3  uint8         `align:"l3"`
	Pad [7]uint8      `align:"pad"`
}

func (v *DeviceValue) String() string {
	return fmt.Sprintf("mac=%s is_l3_dev=%d", v.MAC, v.L3)
}

func (v *DeviceValue) New() bpf.MapValue { return &DeviceValue{} }

// DeviceIterateCallback represents the signature of the callback function
// expected by the IterateWithCallback method, which in turn is used to iterate
// all the keys/values of a device map.
type DeviceIterateCallback func(*DeviceKey, *DeviceValue)

// IterateWithCallback iterates through all the keys/values of a device map,
// passing each key/value pair to the cb callback.
func (m *DeviceMap) IterateWithCallback(cb DeviceIterateCallback) error {
	return m.DumpWithCallback(func(k bpf.MapKey, v bpf.MapValue) {
		key := k.(*DeviceKey)
		value := v.(*DeviceValue)

		cb(key, value)
	})
}

func (m *DeviceMap) init() error {
	if err := m.OpenOrCreate(); err != nil {
		return fmt.Errorf("failed to init bpf map: %w", err)
	}

	return nil
}

func (m *DeviceMap) close() error {
	if err := m.Close(); err != nil {
		return fmt.Errorf("failed to close bpf map: %w", err)
	}

	return nil
}
