// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package maps

import (
	"context"
	"testing"

	"github.com/cilium/hive"
	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/cilium/hive/job"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/maglev"
	"github.com/cilium/cilium/pkg/maps/registry"
	"github.com/cilium/cilium/pkg/option"
)

type lbMapExpectation struct {
	name           string
	maxEntries     uint32
	flags          uint32
	innerValueSize uint32
}

func testLBConfig() loadbalancer.Config {
	return loadbalancer.Config{
		UserConfig: loadbalancer.UserConfig{
			LBServiceMapEntries:     101,
			LBBackendMapEntries:     102,
			LBRevNatEntries:         103,
			LBAffinityMapEntries:    104,
			LBMaglevMapEntries:      105,
			LBSockRevNatEntries:     106,
			LBSourceRangeMapEntries: 107,
		},
	}
}

func configuredRegistry(t *testing.T, cfg loadbalancer.Config, maglevCfg maglev.Config, daemonCfg *option.DaemonConfig) *registry.MapRegistry {
	t.Helper()

	log := hivetest.Logger(t)
	var reg *registry.MapRegistry
	h := hive.New(
		job.Cell,
		cell.Provide(func(jr job.Registry) job.Group {
			health, _ := cell.NewSimpleHealth()
			return jr.NewGroup(health)
		}),
		registry.Cell,
		cell.Invoke(func(r *registry.MapRegistry) error {
			reg = r
			return configure(r, cfg, maglevCfg, daemonCfg)
		}),
	)
	require.NoError(t, h.Populate(log))
	require.NoError(t, h.Start(log, context.Background()))
	t.Cleanup(func() {
		require.NoError(t, h.Stop(log, context.Background()))
	})

	return reg
}

func lbMapExpectations(cfg loadbalancer.Config, maglevCfg maglev.Config, daemonCfg *option.DaemonConfig) []lbMapExpectation {
	noPrealloc := uint32(unix.BPF_F_NO_PREALLOC)
	rdonly := uint32(unix.BPF_F_RDONLY_PROG)
	noCommonLRU := uint32(unix.BPF_F_NO_COMMON_LRU)

	prealloc := uint32(0)
	if !daemonCfg.PreAllocateMaps {
		prealloc = noPrealloc
	}

	lru := uint32(0)
	if daemonCfg.BPFDistributedLRU {
		lru = noCommonLRU
	}

	maglevInnerValueSize := MaglevBackendLen * uint32(maglevCfg.TableSize)

	return []lbMapExpectation{
		{Service4MapV2Name, uint32(cfg.LBServiceMapEntries), prealloc | rdonly, 0},
		{Service6MapV2Name, uint32(cfg.LBServiceMapEntries), prealloc | rdonly, 0},
		{Backend4MapV3Name, uint32(cfg.LBBackendMapEntries), prealloc, 0},
		{Backend6MapV3Name, uint32(cfg.LBBackendMapEntries), prealloc, 0},
		{RevNat4MapName, uint32(cfg.LBRevNatEntries), prealloc, 0},
		{RevNat6MapName, uint32(cfg.LBRevNatEntries), prealloc, 0},
		{AffinityMatchMapName, uint32(cfg.LBAffinityMapEntries), prealloc | rdonly, 0},
		{Affinity4MapName, uint32(cfg.LBAffinityMapEntries), lru, 0},
		{Affinity6MapName, uint32(cfg.LBAffinityMapEntries), lru, 0},
		{MaglevOuter4MapName, uint32(cfg.LBMaglevMapEntries), prealloc | rdonly, maglevInnerValueSize},
		{MaglevOuter6MapName, uint32(cfg.LBMaglevMapEntries), prealloc | rdonly, maglevInnerValueSize},
		{SockRevNat4MapName, uint32(cfg.LBSockRevNatEntries), lru, 0},
		{SockRevNat6MapName, uint32(cfg.LBSockRevNatEntries), lru, 0},
		{SourceRange4MapName, uint32(cfg.LBSourceRangeMapEntries), noPrealloc | rdonly, 0},
		{SourceRange6MapName, uint32(cfg.LBSourceRangeMapEntries), noPrealloc | rdonly, 0},
		{HealthProbe4MapName, uint32(cfg.LBBackendMapEntries), lru, 0},
		{HealthProbe6MapName, uint32(cfg.LBBackendMapEntries), lru, 0},
		{SkipLB4MapName, SkipLBMapMaxEntries, noPrealloc | rdonly, 0},
		{SkipLB6MapName, SkipLBMapMaxEntries, noPrealloc | rdonly, 0},
	}
}

func TestConfigureLBMaps(t *testing.T) {
	cfg := testLBConfig()
	maglevCfg := maglev.Config{TableSize: 1021}

	for _, tc := range []struct {
		name       string
		prealloc   bool
		distribLRU bool
	}{
		{name: "no-prealloc", prealloc: false, distribLRU: false},
		{name: "prealloc", prealloc: true, distribLRU: false},
		{name: "no-prealloc-distributed-lru", prealloc: false, distribLRU: true},
		{name: "prealloc-distributed-lru", prealloc: true, distribLRU: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			daemonCfg := &option.DaemonConfig{
				PreAllocateMaps:   tc.prealloc,
				BPFDistributedLRU: tc.distribLRU,
			}
			reg := configuredRegistry(t, cfg, maglevCfg, daemonCfg)

			for _, want := range lbMapExpectations(cfg, maglevCfg, daemonCfg) {
				spec, err := reg.Get(want.name)
				require.NoError(t, err, want.name)
				require.Equal(t, want.maxEntries, spec.MaxEntries, want.name)
				require.Equal(t, want.flags, spec.Flags, want.name)
				if want.innerValueSize != 0 {
					require.NotNil(t, spec.InnerMap, want.name)
					require.Equal(t, want.innerValueSize, spec.InnerMap.ValueSize, want.name)
				}
			}
		})
	}
}
