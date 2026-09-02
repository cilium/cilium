// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package device

import (
	"encoding/json"
	"fmt"

	"github.com/vishvananda/netlink"
	"go.yaml.in/yaml/v3"
)

type DesiredVRFDeviceSpec struct {
	Name string `json:"name" yaml:"name"`
	// Table is immutable after the link is created.
	Table uint32 `json:"table" yaml:"table"`
}

var _ DesiredDeviceSpec = (*DesiredVRFDeviceSpec)(nil)

func (d *DesiredVRFDeviceSpec) ToNetlink() (netlink.Link, error) {
	return &netlink.Vrf{
		LinkAttrs: netlink.LinkAttrs{Name: d.Name},
		Table:     d.Table,
	}, nil
}

// NeedsRecreate reports whether type or routing table differs.
func (d *DesiredVRFDeviceSpec) NeedsRecreate(existing netlink.Link) bool {
	vrf, ok := existing.(*netlink.Vrf)
	if !ok {
		return true
	}
	return vrf.Table != d.Table
}

func (d *DesiredVRFDeviceSpec) CanModify() bool {
	return false
}

func (d *DesiredVRFDeviceSpec) Properties() string {
	return fmt.Sprintf("Type=vrf, Table=%d", d.Table)
}

func (d *DesiredVRFDeviceSpec) MarshalYAML() (any, error) {
	return yaml.Marshal(*d)
}

func (d *DesiredVRFDeviceSpec) MarshalJSON() ([]byte, error) {
	return json.Marshal(*d)
}
