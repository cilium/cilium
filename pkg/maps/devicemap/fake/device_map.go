// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package fake

import (
	"github.com/cilium/ebpf"

	"github.com/cilium/cilium/pkg/mac"
	"github.com/cilium/cilium/pkg/maps/devicemap"
)

type DeviceKey = devicemap.DeviceKey
type DeviceValue = devicemap.DeviceValue

type fakeDeviceMap struct {
	Entries map[DeviceKey]DeviceValue
}

func NewFakeDeviceMap() *fakeDeviceMap {
	return &fakeDeviceMap{
		Entries: map[DeviceKey]DeviceValue{},
	}
}

func (f fakeDeviceMap) Lookup(ifIndex uint32) (DeviceValue, error) {
	key := DeviceKey{IfIndex: ifIndex}
	info, exists := f.Entries[key]
	if exists {
		return info, nil
	}
	return info, ebpf.ErrKeyNotExist
}

func (f fakeDeviceMap) Update(ifIndex uint32, mac mac.Uint64MAC, l3 uint8) error {
	key := DeviceKey{IfIndex: ifIndex}
	f.Entries[key] = DeviceValue{MAC: mac, L3: l3}
	return nil
}

func (f fakeDeviceMap) Delete(ifIndex uint32) error {
	key := DeviceKey{IfIndex: ifIndex}
	delete(f.Entries, key)
	return nil
}

func (f fakeDeviceMap) IterateWithCallback(cb devicemap.DeviceIterateCallback) error {
	for key, info := range f.Entries {
		cb(&key, &info)
	}
	return nil
}
