// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package device

import (
	"cmp"
	"fmt"
	"strings"

	"github.com/cilium/statedb"
	"github.com/cilium/statedb/index"
	"github.com/cilium/statedb/reconciler"
	"github.com/vishvananda/netlink"
)

type DeviceOwner struct {
	Name string `json:"name" yaml:"name"`
}

type DesiredDeviceKey struct {
	Owner DeviceOwner
	Name  string
}

func (k DesiredDeviceKey) Key() index.Key {
	return index.String(k.Owner.Name + "/" + k.Name)
}

func (k DesiredDeviceKey) String() string {
	if k.Owner.Name == "" {
		return k.Name
	}
	return fmt.Sprintf("%s/%s", k.Owner.Name, k.Name)
}

var desiredDeviceKeyBinaryVersion = 1

func (k *DesiredDeviceKey) MarshalBinary() ([]byte, error) {
	var buf []byte
	buf = append(buf, byte(desiredDeviceKeyBinaryVersion))
	buf = append(buf, k.Key()...)
	return buf, nil
}

func (k *DesiredDeviceKey) UnmarshalBinary(data []byte) error {
	if len(data) < 1 {
		return fmt.Errorf("invalid data length: %d", len(data))
	}

	if data[0] != byte(desiredDeviceKeyBinaryVersion) {
		return fmt.Errorf("unsupported DesiredDeviceKey version: %d", data[0])
	}
	parsedDeviceData := strings.Split(string(data[1:]), "/")
	if len(parsedDeviceData) != 2 {
		return fmt.Errorf("unsupported DesiredDeviceKey format")
	}

	k.Owner = DeviceOwner{
		Name: parsedDeviceData[0],
	}
	k.Name = parsedDeviceData[1] // potentially check length, device size should not be > 16 bytes.
	return nil
}

func (dd *DesiredDevice) GetKey() DesiredDeviceKey {
	return DesiredDeviceKey{
		Owner: dd.Owner,
		Name:  dd.Name,
	}
}

type DesiredDeviceSpec interface {
	ToNetlink() (netlink.Link, error)
	Properties() string
	MarshalJSON() ([]byte, error)
	MarshalYAML() (any, error)
}

type DesiredDevice struct {
	Owner      DeviceOwner       `json:"owner" yaml:"owner"`
	Name       string            `json:"name" yaml:"name"`
	DeviceSpec DesiredDeviceSpec `json:"spec" yaml:"spec"`

	status reconciler.Status
}

func (dd *DesiredDevice) TableHeader() []string {
	return []string{
		"Owner",
		"Name",
		"Properties",
		"Status",
	}
}

func (dd *DesiredDevice) TableRow() []string {
	return []string{
		// owner name
		cmp.Or(dd.Owner.Name, "N/A"),
		// device name
		dd.Name,
		// device properties
		cmp.Or(dd.DeviceSpec.Properties(), "N/A"),
		// reconciler status
		dd.status.String(),
	}
}

func (dd *DesiredDevice) Validate() error {
	if dd.Owner.Name == "" {
		return fmt.Errorf("owner cannot be empty")
	}

	if dd.Name == "" {
		return fmt.Errorf("device name cannot be empty")
	}

	if len(dd.Name) > 15 {
		return fmt.Errorf("device name %q exceeds maximum length of 15 characters", dd.Name)
	}

	if dd.DeviceSpec == nil {
		return fmt.Errorf("device spec cannot be nil")
	}

	nl, err := dd.DeviceSpec.ToNetlink()
	if err != nil {
		return fmt.Errorf("failed to translate to netlink link: %w", err)
	}

	if nl.Attrs().Name != dd.Name {
		return fmt.Errorf("device name %s does not match with netlink link name %s", dd.Name, nl.Attrs().Name)
	}

	return nil
}

func (dd *DesiredDevice) SetStatus(s reconciler.Status) *DesiredDevice {
	ndd := *dd
	ndd.status = s
	return &ndd
}

func (dd *DesiredDevice) GetStatus() reconciler.Status {
	return dd.status
}

func (dd *DesiredDevice) Clone() *DesiredDevice {
	dd2 := *dd
	return &dd2
}

var (
	DesiredDeviceIndex = statedb.Index[*DesiredDevice, DesiredDeviceKey]{
		Name: "id",
		FromObject: func(obj *DesiredDevice) index.KeySet {
			return index.NewKeySet(obj.GetKey().Key())
		},
		FromKey:    DesiredDeviceKey.Key,
		FromString: index.FromString,
		Unique:     true,
	}
	DesiredDeviceNameIndex = statedb.Index[*DesiredDevice, string]{
		Name: "name",
		FromObject: func(obj *DesiredDevice) index.KeySet {
			return index.NewKeySet(index.String(obj.Name))
		},
		FromKey:    index.String,
		FromString: index.FromString,
		Unique:     true,
	}
)

func newDesiredDeviceTable(db *statedb.DB) (statedb.RWTable[*DesiredDevice], error) {
	return statedb.NewTable(
		db,
		"desired-devices",
		DesiredDeviceIndex,
		DesiredDeviceNameIndex,
	)
}
