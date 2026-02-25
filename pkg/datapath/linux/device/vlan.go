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
	ParentIndex int
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

func (d *DesiredVLANDeviceSpec) Properties() string {
	return fmt.Sprintf("Type=vlan, ParentDevice=%s, VLAN=%d", d.ParentName, d.VLANID)
}

func (d *DesiredVLANDeviceSpec) MarshalYAML() (any, error) {
	return yaml.Marshal(*d)
}

func (d *DesiredVLANDeviceSpec) MarshalJSON() ([]byte, error) {
	return json.Marshal(*d)
}
