// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package maps

import (
	"fmt"

	"golang.org/x/sys/unix"

	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/maglev"
	"github.com/cilium/cilium/pkg/maps/registry"
	"github.com/cilium/cilium/pkg/option"
)

// patchMode selects how the map flags are updated.
type patchMode uint8

const (
	// patchCondPrealloc mirrors CONDITIONAL_PREALLOC: preallocation follows
	// --preallocate-bpf-maps.
	patchCondPrealloc patchMode = iota

	// patchNoPrealloc mirrors a hardcoded BPF_F_NO_PREALLOC. The flag is set
	// regardless of --preallocate-bpf-maps.
	patchNoPrealloc

	// patchCondLRU mirrors LRU_MEM_FLAVOR: --bpf-distributed-lru controls
	// BPF_F_NO_COMMON_LRU.
	patchCondLRU
)

// configure patches the load-balancing map specs in the MapRegistry with the
// configured sizes and memory flags. [BPFLBMaps] creates the maps from the
// specs in the registry, so the maps created by the agent and the maps created
// by the loader share the same specs regardless of the startup order.
func configure(reg *registry.MapRegistry, cfg loadbalancer.Config, maglevCfg maglev.Config, daemonConfig *option.DaemonConfig) error {
	// MapSpecPatch.Apply() replaces the full flags field, so the runtime
	// memory flags have to be replicated here in addition to the map size.
	modify := func(m *registry.MapSpecPatch, entries int, mode patchMode) {
		m.MaxEntries = uint32(entries)

		switch mode {
		case patchCondPrealloc:
			if daemonConfig.PreAllocateMaps {
				m.Flags &^= unix.BPF_F_NO_PREALLOC
			} else {
				m.Flags |= unix.BPF_F_NO_PREALLOC
			}
		case patchNoPrealloc:
			m.Flags |= unix.BPF_F_NO_PREALLOC
		case patchCondLRU:
			if daemonConfig.BPFDistributedLRU {
				m.Flags |= unix.BPF_F_NO_COMMON_LRU
			} else {
				m.Flags &^= unix.BPF_F_NO_COMMON_LRU
			}
		}
	}

	maglevInnerValueSize := MaglevBackendLen * uint32(maglevCfg.TableSize)

	patches := []struct {
		name    string
		entries int
		mode    patchMode
		// innerValueSize, if non-zero, overrides the value size of the inner
		// map. Currently only the maglev inner map depends on the runtime
		// configuration (--bpf-lb-maglev-table-size).
		innerValueSize uint32
	}{
		{name: Service4MapV2Name, entries: cfg.LBServiceMapEntries, mode: patchCondPrealloc},
		{name: Service6MapV2Name, entries: cfg.LBServiceMapEntries, mode: patchCondPrealloc},
		{name: Backend4MapV3Name, entries: cfg.LBBackendMapEntries, mode: patchCondPrealloc},
		{name: Backend6MapV3Name, entries: cfg.LBBackendMapEntries, mode: patchCondPrealloc},
		{name: RevNat4MapName, entries: cfg.LBRevNatEntries, mode: patchCondPrealloc},
		{name: RevNat6MapName, entries: cfg.LBRevNatEntries, mode: patchCondPrealloc},
		{name: AffinityMatchMapName, entries: cfg.LBAffinityMapEntries, mode: patchCondPrealloc},
		{name: Affinity4MapName, entries: cfg.LBAffinityMapEntries, mode: patchCondLRU},
		{name: Affinity6MapName, entries: cfg.LBAffinityMapEntries, mode: patchCondLRU},
		{name: MaglevOuter4MapName, entries: cfg.LBMaglevMapEntries, mode: patchCondPrealloc, innerValueSize: maglevInnerValueSize},
		{name: MaglevOuter6MapName, entries: cfg.LBMaglevMapEntries, mode: patchCondPrealloc, innerValueSize: maglevInnerValueSize},
		{name: SockRevNat4MapName, entries: cfg.LBSockRevNatEntries, mode: patchCondLRU},
		{name: SockRevNat6MapName, entries: cfg.LBSockRevNatEntries, mode: patchCondLRU},
		{name: SourceRange4MapName, entries: cfg.LBSourceRangeMapEntries, mode: patchNoPrealloc},
		{name: SourceRange6MapName, entries: cfg.LBSourceRangeMapEntries, mode: patchNoPrealloc},
		{name: HealthProbe4MapName, entries: cfg.LBBackendMapEntries, mode: patchCondLRU},
		{name: HealthProbe6MapName, entries: cfg.LBBackendMapEntries, mode: patchCondLRU},
		{name: SkipLB4MapName, entries: SkipLBMapMaxEntries, mode: patchNoPrealloc},
		{name: SkipLB6MapName, entries: SkipLBMapMaxEntries, mode: patchNoPrealloc},
	}

	for _, p := range patches {
		entries, mode, innerValueSize := p.entries, p.mode, p.innerValueSize
		var missingInnerMap bool
		if err := reg.Modify(p.name, func(m *registry.MapSpecPatch) {
			modify(m, entries, mode)
			if innerValueSize != 0 {
				if m.InnerMap == nil {
					missingInnerMap = true
					return
				}
				m.InnerMap.ValueSize = innerValueSize
			}
		}); err != nil {
			return fmt.Errorf("configure %s: %w", p.name, err)
		}
		if missingInnerMap {
			return fmt.Errorf("configure %s: map has no inner map spec", p.name)
		}
	}

	return nil
}
