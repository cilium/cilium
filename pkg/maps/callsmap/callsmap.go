// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package callsmap

const (
	// MapName is the prefix of the BPF map.
	MapName = "cilium_calls_"
	// CustomCallsMapName is the name prefix for the per-endpoint prog
	// array maps used for loading user-defined eBPF programs.
	CustomCallsMapName = MapName + "custom_"
)

var (
	// HostMapName and NetdevMapName are name prefixes for the host
	// datapath BPF maps. They must be different but have the same length.
	HostMapName   = MapName + "hostns_"
	NetdevMapName = MapName + "netdev_"
)
