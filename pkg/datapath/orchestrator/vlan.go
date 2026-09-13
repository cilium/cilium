// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package orchestrator

import (
	"cmp"
	"fmt"
	"slices"

	"github.com/vishvananda/netlink"

	"github.com/cilium/cilium/pkg/datapath/config"
	"github.com/cilium/cilium/pkg/datapath/linux/safenetlink"
	"github.com/cilium/cilium/pkg/datapath/tables"
	"github.com/cilium/cilium/pkg/datapath/types"
)

const maxVLANFilterEntries = len(types.VlanFilterConfig{}.VlanIds)

func resolveVLANFilters(nativeDevices []*tables.Device, bypass []int) (config.VLANFilter, error) {
	if slices.Contains(bypass, 0) {
		return config.VLANFilter{AllowAll: true}, nil
	}

	links, err := safenetlink.LinkList()
	if err != nil {
		return config.VLANFilter{}, fmt.Errorf("listing network links: %w", err)
	}

	return resolveVLANFilterEntries(nativeDevices, links, bypass)
}

func resolveVLANFilterEntries(
	nativeDevices []*tables.Device,
	links []netlink.Link,
	bypass []int,
) (config.VLANFilter, error) {
	devices := deviceMap(nativeDevices)
	allowedVLANs := allowedVLANMap(bypass)

	entries := make([]config.VLANFilterEntry, 0)
	for _, link := range links {
		vlan, ok := link.(*netlink.Vlan)
		if !ok {
			continue
		}

		if !vlanAllowed(devices, allowedVLANs, vlan) {
			continue
		}

		entries = append(
			entries, config.VLANFilterEntry{IfIndex: vlan.ParentIndex, VLAN: uint16(vlan.VlanId)},
		)
	}

	if len(entries) > maxVLANFilterEntries {
		return config.VLANFilter{}, fmt.Errorf(
			"too many VLAN filter entries: found %d, maximum supported is %d; use --vlan-bpf-bypass=0 to allow all VLANs",
			len(entries),
			maxVLANFilterEntries,
		)
	}

	slices.SortFunc(entries, cmpVLANFilterEntries)
	return config.VLANFilter{Entries: entries}, nil
}

func deviceMap(nativeDevices []*tables.Device) map[int]struct{} {
	devices := make(map[int]struct{}, len(nativeDevices))
	for i := range nativeDevices {
		devices[nativeDevices[i].Index] = struct{}{}
	}
	return devices
}

func allowedVLANMap(bypass []int) map[int]struct{} {
	allowed := make(map[int]struct{}, len(bypass))
	for i := range bypass {
		allowed[bypass[i]] = struct{}{}
	}
	return allowed
}

func vlanAllowed(devices, allowedVLANs map[int]struct{}, vlan *netlink.Vlan) bool {
	// ParentIndex identifies the underlying device carrying the tagged packet,
	// while Index identifies the VLAN device created on top of that parent.
	_, parentSelected := devices[vlan.ParentIndex]
	_, deviceSelected := devices[vlan.Index]
	_, explicitlyAllowed := allowedVLANs[vlan.VlanId]
	return parentSelected && (deviceSelected || explicitlyAllowed)
}

func cmpVLANFilterEntries(a, b config.VLANFilterEntry) int {
	if a.IfIndex != b.IfIndex {
		return cmp.Compare(a.IfIndex, b.IfIndex)
	}
	return cmp.Compare(a.VLAN, b.VLAN)
}
