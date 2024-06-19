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
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/maglev"
	"github.com/cilium/cilium/pkg/option"
)

// Cell creates and opens the load-balancer BPF maps (services, backends,
// maglev, affinity, reverse_nat, reverse_sk and source_range) and implements
// the [types.LBMap] API for manipulating them.
var Cell = cell.Module(
	"lbmap",
	"BPF maps for service load-balancing",

	configCell,
	cell.Provide(New),
)

type Config interface {
	ServiceMapMaxEntries() int
	BackendMapMaxEntries() int
	RevNatMapMaxEntries() int
	AffinityMapMaxEntries() int
	SourceRangeMapMaxEntries() int
	MaglevMapMaxEntries() int
}

type params struct {
	cell.In

	Log          *slog.Logger
	Lifecycle    cell.Lifecycle
	DaemonConfig *option.DaemonConfig
	Config       Config
}

func New(p params) (types.LBMap, mapOut, error) {
	lbmapInitParams := InitParams{
		IPv4:                     p.DaemonConfig.EnableIPv4,
		IPv6:                     p.DaemonConfig.EnableIPv6,
		MaxSockRevNatMapEntries:  p.DaemonConfig.SockRevNatEntries,
		ServiceMapMaxEntries:     p.Config.ServiceMapMaxEntries(),
		BackEndMapMaxEntries:     p.Config.BackendMapMaxEntries(),
		RevNatMapMaxEntries:      p.Config.RevNatMapMaxEntries(),
		AffinityMapMaxEntries:    p.Config.AffinityMapMaxEntries(),
		SourceRangeMapMaxEntries: p.Config.SourceRangeMapMaxEntries(),
		MaglevMapMaxEntries:      p.Config.MaglevMapMaxEntries(),
	}

	if err := nodePortAlgInit(p.DaemonConfig); err != nil {
		return nil, mapOut{}, err
	}

	// Init to allocate all the map objects. Creation will happen in the start
	// hook.
	Init(lbmapInitParams)

	// Figure out which maps to open or delete when we start.
	toOpen := []*bpf.Map{}
	toDelete := []*bpf.Map{}

	if p.DaemonConfig.EnableSessionAffinity {
		toOpen = append(toOpen, AffinityMatchMap)
	}
	if p.DaemonConfig.EnableIPv6 {
		toOpen = append(toOpen, Service6MapV2, Backend6MapV3, RevNat6Map)
		if !p.DaemonConfig.RestoreState {
			toDelete = append(toDelete, Service6MapV2, Backend6MapV3, RevNat6Map)
		}
		if p.DaemonConfig.EnableSessionAffinity {
			toOpen = append(toOpen, Affinity6Map)
		}
		if p.DaemonConfig.EnableSocketLB {
			toOpen = append(toOpen, SockRevNat6Map)
		}
		if p.DaemonConfig.EnableSVCSourceRangeCheck {
			toOpen = append(toOpen, SourceRange6Map)
		}
	}
	if p.DaemonConfig.EnableIPv4 {
		toOpen = append(toOpen, Service4MapV2, Backend4MapV3, RevNat4Map)
		if !p.DaemonConfig.RestoreState {
			toDelete = append(toDelete, Service4MapV2, Backend4MapV3, RevNat4Map)
		}
		if p.DaemonConfig.EnableSocketLB {
			toOpen = append(toOpen, SockRevNat4Map)
		}
		if p.DaemonConfig.EnableSessionAffinity {
			toOpen = append(toOpen, Affinity4Map)
		}
		if p.DaemonConfig.EnableSVCSourceRangeCheck {
			toOpen = append(toOpen, SourceRange4Map)
		}
	}

	log := p.Log
	p.Lifecycle.Append(
		cell.Hook{
			OnStart: func(_ cell.HookContext) error {
				if p.DaemonConfig.NodePortAlg == option.NodePortAlgMaglev {
					if err := InitMaglevMaps(p.DaemonConfig.EnableIPv4, p.DaemonConfig.EnableIPv6, uint32(p.DaemonConfig.MaglevTableSize)); err != nil {
						return fmt.Errorf("initializing maglev maps: %w", err)
					}
				}

				for _, m := range toOpen {
					if err := m.OpenOrCreate(); err != nil {
						return fmt.Errorf("opening BPF map %s: %w", m.Name(), err)
					}
				}
				for _, m := range toDelete {
					if err := m.DeleteAll(); err != nil {
						return err
					}
				}

				var (
					v2BackendMapExistsV4 bool
					v2BackendMapExistsV6 bool
				)
				if p.DaemonConfig.EnableIPv6 {
					v2BackendMapExistsV6 = Backend6MapV2.Open() == nil
				}
				if p.DaemonConfig.EnableIPv4 {
					v2BackendMapExistsV4 = Backend4MapV2.Open() == nil
				}
				if v2BackendMapExistsV4 || v2BackendMapExistsV6 {
					log.Info("Backend map v2 exists. Migrating entries to backend map v3.")
					if err := populateBackendMapV3FromV2(v2BackendMapExistsV4, v2BackendMapExistsV6); err != nil {
						log.Warn("Error populating V3 map from V2 map, might interrupt existing connections during upgrade", logfields.Error, err)
					}
				}

				return nil
			},
		},
	)

	maglev := p.DaemonConfig.NodePortAlg == option.NodePortAlgMaglev
	maglevTableSize := p.DaemonConfig.MaglevTableSize
	m := &LBBPFMap{}
	if maglev {
		m.maglevBackendIDsBuffer = make([]loadbalancer.BackendID, maglevTableSize)
		m.maglevTableSize = uint64(maglevTableSize)
	}
	return m, newMapOut(toOpen), nil
}

func nodePortAlgInit(cfg *option.DaemonConfig) error {
	if cfg.NodePortAlg != option.NodePortAlgRandom &&
		cfg.NodePortAlg != option.NodePortAlgMaglev {
		return fmt.Errorf("Invalid value for --%s: %s", option.NodePortAlg, cfg.NodePortAlg)
	}

	if cfg.NodePortAlg == option.NodePortAlgMaglev {
		// Maglev enabled, initialize the maglev package for computing
		// the lookup tables.

		// "Let N be the size of a VIP's backend pool." [...] "In practice, we choose M to be
		// larger than 100 x N to ensure at most a 1% difference in hash space assigned to
		// backends." (from Maglev paper, page 6)
		supportedPrimes := []int{251, 509, 1021, 2039, 4093, 8191, 16381, 32749, 65521, 131071}
		found := false
		for _, prime := range supportedPrimes {
			if option.Config.MaglevTableSize == prime {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("Invalid value for --%s: %d, supported values are: %v",
				option.MaglevTableSize, option.Config.MaglevTableSize, supportedPrimes)
		}
		if err := maglev.Init(
			option.Config.MaglevHashSeed,
			uint64(option.Config.MaglevTableSize),
		); err != nil {
			return fmt.Errorf("Failed to initialize maglev hash seeds: %w", err)
		}
	}
	return nil
}

// mapOut is the set of BpfMap's opened by this package. The datapath loader depends
// on the group of all BPF maps in order for the maps to be opened before the loader
// starts.
type mapOut struct {
	cell.Out
	Maps []bpf.BpfMap `group:"bpf-maps,flatten"`
}

func newMapOut(maps []*bpf.Map) (out mapOut) {
	for _, m := range maps {
		out.Maps = append(out.Maps, m)
	}
	return
}
