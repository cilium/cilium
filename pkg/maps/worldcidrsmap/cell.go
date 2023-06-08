// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package worldcidrsmap

import (
	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/hive/cell"
)

// Cell provides the worldcidrsmap.Map which contains information about node IDs and their IP addresses.
var Cell = cell.Module(
	"worldcidrs-map",
	"eBPF storing world cidrs -- used for highscale ipcache",

	cell.Provide(newWorldCidrsMap),
)

func newWorldCidrsMap() bpf.MapOut[Map] {
	m := newWorldCIDRsMap()

	return bpf.NewMapOut(Map(m))
}
