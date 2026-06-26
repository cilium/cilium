// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package device

import (
	"encoding/json"
	"fmt"

	"github.com/vishvananda/netlink"
	"go.yaml.in/yaml/v3"
)

type DesiredVLANDeviceSpec struct {
	Name        string `json:"name" yaml:"name"`
	VLANID      int    `json:"vlanID" yaml:"vlanID"`
	MTU         int    `json:"mtu" yaml:"mtu"`
	ParentName  string `json:"parentName" yaml:"parentName"`
	ParentIndex int    `json:"parentIndex" yaml:"parentIndex"`
}

var _ DesiredDeviceSpec = (*DesiredVLANDeviceSpec)(nil)

func (d *DesiredVLANDeviceSpec) ToNetlink() (netlink.Link, error) {
	return &netlink.Vlan{
		LinkAttrs: netlink.LinkAttrs{
			Name:        d.Name,
			MTU:         d.MTU,
			ParentIndex: d.ParentIndex,
		},
		VlanId: d.VLANID,
	}, nil
}

// NeedsRecreate reports whether the existing VLAN device must be recreated. The
// VLAN ID and parent interface are immutable, so a recreate is only
// needed when one of those differs from the desired spec. Mutable attributes (e.g.
// MTU) are handled in-place via LinkModify.
func (d *DesiredVLANDeviceSpec) NeedsRecreate(existing netlink.Link) bool {
	vlan, ok := existing.(*netlink.Vlan)
	if !ok {
		// Existing device isn't a VLAN (name collision with a different type) —
		// recreate to converge to the desired type.
		return true
	}
	return vlan.VlanId != d.VLANID || vlan.ParentIndex != d.ParentIndex
}

func (d *DesiredVLANDeviceSpec) Properties() string {
	return fmt.Sprintf("Type=vlan, ParentDevice=%s (%d), VLAN=%d",
		d.ParentName, d.ParentIndex, d.VLANID)
}

func (d *DesiredVLANDeviceSpec) MarshalYAML() (any, error) {
	return yaml.Marshal(*d)
}

func (d *DesiredVLANDeviceSpec) MarshalJSON() ([]byte, error) {
	return json.Marshal(*d)
}
