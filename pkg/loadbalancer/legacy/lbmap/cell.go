// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package lbmap

import (
	"fmt"
	"log/slog"

	"github.com/cilium/hive/cell"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/maglev"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/option"
)

var Cell = cell.Module(
	"lbmap-legacy",
	"The old load-balancer map abstraction",

	cell.Provide(func(lc cell.Lifecycle, registry *metrics.Registry, log *slog.Logger, cfg loadbalancer.Config, maglev *maglev.Maglev) bpf.MapOut[types.LBMap] {
		if cfg.EnableExperimentalLB {
			// The experimental control-plane comes with its own LBMap implementation.
			return bpf.NewMapOut[types.LBMap](nil)
		}
		lc.Append(cell.Hook{
			OnStart: func(_ cell.HookContext) error {
				return onStart(registry, log, cfg, maglev.Config)
			},
		})
		return bpf.NewMapOut[types.LBMap](New(log, cfg, maglev))
	}),
)

func onStart(registry *metrics.Registry, log *slog.Logger, lbConfig loadbalancer.Config, maglevConfig maglev.Config) error {
	lbmapInitParams := InitParams{
		IPv4:                     option.Config.EnableIPv4,
		IPv6:                     option.Config.EnableIPv6,
		MaxSockRevNatMapEntries:  lbConfig.LBSockRevNatEntries,
		ServiceMapMaxEntries:     lbConfig.LBServiceMapEntries,
		BackEndMapMaxEntries:     lbConfig.LBBackendMapEntries,
		RevNatMapMaxEntries:      lbConfig.LBRevNatEntries,
		AffinityMapMaxEntries:    lbConfig.LBAffinityMapEntries,
		SourceRangeMapMaxEntries: lbConfig.LBSourceRangeMapEntries,
		MaglevMapMaxEntries:      lbConfig.LBMaglevMapEntries,
	}
	Init(registry, lbmapInitParams)

	if option.Config.EnableSessionAffinity {
		if err := AffinityMatchMap.OpenOrCreate(); err != nil {
			return fmt.Errorf("initializing affinity match map: %w", err)
		}
		if option.Config.EnableIPv4 {
			if err := Affinity4Map.OpenOrCreate(); err != nil {
				return fmt.Errorf("initializing affinity v4 map: %w", err)
			}
		}
		if option.Config.EnableIPv6 {
			if err := Affinity6Map.OpenOrCreate(); err != nil {
				return fmt.Errorf("initializing affinity v6 map: %w", err)
			}
		}
	}

	if option.Config.EnableSVCSourceRangeCheck {
		if option.Config.EnableIPv4 {
			if err := SourceRange4Map.OpenOrCreate(); err != nil {
				return fmt.Errorf("initializing source range v4 map: %w", err)
			}
		}
		if option.Config.EnableIPv6 {
			if err := SourceRange6Map.OpenOrCreate(); err != nil {
				return fmt.Errorf("initializing source range v6 map: %w", err)
			}
		}
	}

	if lbConfig.LBAlgorithm == loadbalancer.LBAlgorithmMaglev ||
		lbConfig.AlgorithmAnnotation {
		if err := InitMaglevMaps(log, option.Config.EnableIPv4, option.Config.EnableIPv6, uint32(maglevConfig.TableSize)); err != nil {
			return fmt.Errorf("initializing maglev maps: %w", err)
		}
	}

	// Create and open the SkipLBMap to pin it before the loader.
	skiplbmap, err := NewSkipLBMap(log)
	if err == nil {
		err = skiplbmap.OpenOrCreate()
	}
	if err != nil {
		return fmt.Errorf("initializing local redirect policy maps: %w", err)
	}

	return nil

}
