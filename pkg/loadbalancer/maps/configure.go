// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package maps

import (
	"fmt"

	"golang.org/x/sys/unix"

	"github.com/cilium/cilium/pkg/loadbalancer"
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
// configured sizes and memory flags. The maps themselves are created by
// [BPFLBMaps] from the same configuration; the patches make sure the specs
// used by the loader match the maps created here.
func configure(reg *registry.MapRegistry, cfg loadbalancer.Config, daemonConfig *option.DaemonConfig) error {
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

	patches := []struct {
		name    string
		entries int
		mode    patchMode
	}{
		{Service4MapV2Name, cfg.LBServiceMapEntries, patchCondPrealloc},
		{Service6MapV2Name, cfg.LBServiceMapEntries, patchCondPrealloc},
		{Backend4MapV3Name, cfg.LBBackendMapEntries, patchCondPrealloc},
		{Backend6MapV3Name, cfg.LBBackendMapEntries, patchCondPrealloc},
		{RevNat4MapName, cfg.LBRevNatEntries, patchCondPrealloc},
		{RevNat6MapName, cfg.LBRevNatEntries, patchCondPrealloc},
		{AffinityMatchMapName, cfg.LBAffinityMapEntries, patchCondPrealloc},
		{Affinity4MapName, cfg.LBAffinityMapEntries, patchCondLRU},
		{Affinity6MapName, cfg.LBAffinityMapEntries, patchCondLRU},
		{MaglevOuter4MapName, cfg.LBMaglevMapEntries, patchCondPrealloc},
		{MaglevOuter6MapName, cfg.LBMaglevMapEntries, patchCondPrealloc},
		{HealthProbe4MapName, cfg.LBBackendMapEntries, patchCondLRU},
		{HealthProbe6MapName, cfg.LBBackendMapEntries, patchCondLRU},
		{SkipLB4MapName, SkipLBMapMaxEntries, patchNoPrealloc},
		{SkipLB6MapName, SkipLBMapMaxEntries, patchNoPrealloc},
	}

	for _, p := range patches {
		entries, mode := p.entries, p.mode
		if err := reg.Modify(p.name, func(m *registry.MapSpecPatch) {
			modify(m, entries, mode)
		}); err != nil {
			return fmt.Errorf("configure %s: %w", p.name, err)
		}
	}

	return nil
}
