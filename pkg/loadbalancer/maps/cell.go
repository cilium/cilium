// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package maps

import (
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/hive/cell"
	"golang.org/x/sys/unix"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/loadbalancer"
	mapregistry "github.com/cilium/cilium/pkg/maps/registry"
)

// Provides [LBMap] a wrapper around the load-balancing BPF maps
var Cell = cell.Module(
	"loadbalancer-maps",
	"Load-balancing BPF maps",

	// Provide [lbmaps], abstraction for the load-balancing BPF map access.
	cell.Provide(newLBMaps),

	// Configure the map specs of the load-balancing BPF maps.
	cell.Invoke(configureLBMaps),

	// Provide the 'lb/' script commands for debugging and testing.
	cell.Provide(scriptCommands),

	// Register a periodic job to update the BPF map pressure metrics.
	cell.Invoke(registerPressureMetricsReporter),
)

func configureLBMaps(reg *mapregistry.MapRegistry, cfg loadbalancer.Config) error {
	hashFlags := bpf.GetMapMemoryFlags(ebpf.Hash) | unix.BPF_F_RDONLY_PROG
	hashOfMapsFlags := bpf.GetMapMemoryFlags(ebpf.HashOfMaps) | unix.BPF_F_RDONLY_PROG
	lpmFlags := bpf.GetMapMemoryFlags(ebpf.LPMTrie) | unix.BPF_F_RDONLY_PROG
	lruFlags := bpf.GetMapMemoryFlags(ebpf.LRUHash)

	for _, m := range []struct {
		name       string
		flags      uint32
		maxEntries int
	}{
		{Service4MapV2Name, hashFlags, cfg.LBServiceMapEntries},
		{Service6MapV2Name, hashFlags, cfg.LBServiceMapEntries},
		{Backend4MapV3Name, hashFlags, cfg.LBBackendMapEntries},
		{Backend6MapV3Name, hashFlags, cfg.LBBackendMapEntries},
		{RevNat4MapName, hashFlags, cfg.LBRevNatEntries},
		{RevNat6MapName, hashFlags, cfg.LBRevNatEntries},
		{AffinityMatchMapName, hashFlags, cfg.LBAffinityMapEntries},
		{Affinity4MapName, lruFlags, cfg.LBAffinityMapEntries},
		{Affinity6MapName, lruFlags, cfg.LBAffinityMapEntries},
		{MaglevOuter4MapName, hashOfMapsFlags, cfg.LBMaglevMapEntries},
		{MaglevOuter6MapName, hashOfMapsFlags, cfg.LBMaglevMapEntries},
		{SourceRange4MapName, lpmFlags, cfg.LBSourceRangeMapEntries},
		{SourceRange6MapName, lpmFlags, cfg.LBSourceRangeMapEntries},
		{SockRevNat4MapName, lruFlags, cfg.LBSockRevNatEntries},
		{SockRevNat6MapName, lruFlags, cfg.LBSockRevNatEntries},
		{HealthProbe4MapName, lruFlags, cfg.LBBackendMapEntries},
		{HealthProbe6MapName, lruFlags, cfg.LBBackendMapEntries},
	} {
		if err := reg.Modify(m.name, func(patch *mapregistry.MapSpecPatch) {
			patch.Flags = m.flags
			patch.MaxEntries = uint32(m.maxEntries)
		}); err != nil {
			return fmt.Errorf("error setting %s map flags and max entries: %w", m.name, err)
		}
	}

	return nil
}
