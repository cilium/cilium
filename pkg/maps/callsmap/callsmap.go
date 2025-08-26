// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package callsmap

const (
	// MapName is the prefix of the per-endpoint tail call map.
	MapName = "cilium_calls_"

	// CustomCallsMapName is the name prefix for the per-endpoint prog
	// array maps used for loading user-defined eBPF programs.
	CustomCallsMapName = MapName + "custom_"

	// HostMapName and NetdevMapName are name prefixes for bpf_host's tail call
	// maps when attached to different interfaces.
	//
	// bpf_host attached to a cilium_host will use HostMapName. Attaching to
	// cilium_net and external interfaces will use NetdevMapName.
	HostMapName   = MapName + "hostns_"
	NetdevMapName = MapName + "netdev_"
)
