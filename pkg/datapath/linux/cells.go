package linux

import (
	"fmt"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/maglev"
	"github.com/cilium/cilium/pkg/maps/lbmap"
	serviceConfig "github.com/cilium/cilium/pkg/service/config"
)

var LBMapCell = cell.Module(
	"lbmap",
	"LBMap manages the BPF maps for load-balancing",

	cell.Provide(newLBMap),
)

func newLBMap(lc hive.Lifecycle, cfg serviceConfig.ServiceConfig) types.LBMap {
	m := lbmap.New()

	lc.Append(
		hive.Hook{
			OnStart: func(hive.HookContext) error {
				return initLBMaps(cfg, false, true, false, false /* TODO */)
			},
		})

	return m
}

func initLBMaps(cfg serviceConfig.ServiceConfig, ipv6, ipv4, sockMaps, restore bool) error {
	var (
		v1BackendMapExistsV4 bool
		v1BackendMapExistsV6 bool
	)

	toOpen := []*bpf.Map{}
	toDelete := []*bpf.Map{}
	if ipv6 {
		toOpen = append(toOpen, lbmap.Service6MapV2, lbmap.Backend6MapV2, lbmap.RevNat6Map)
		if !restore {
			toDelete = append(toDelete, lbmap.Service6MapV2, lbmap.Backend6MapV2, lbmap.RevNat6Map)
		}
		if sockMaps {
			if err := lbmap.CreateSockRevNat6Map(); err != nil {
				return err
			}
		}
		v1BackendMapExistsV6 = lbmap.Backend6Map.Open() == nil
	}
	if ipv4 {
		toOpen = append(toOpen, lbmap.Service4MapV2, lbmap.Backend4MapV2, lbmap.RevNat4Map)
		if !restore {
			toDelete = append(toDelete, lbmap.Service4MapV2, lbmap.Backend4MapV2, lbmap.RevNat4Map)
		}
		if sockMaps {
			if err := lbmap.CreateSockRevNat4Map(); err != nil {
				return err
			}
		}
		v1BackendMapExistsV4 = lbmap.Backend4Map.Open() == nil
	}

	for _, m := range toOpen {
		if _, err := m.OpenOrCreate(); err != nil {
			return err
		}
	}
	for _, m := range toDelete {
		if err := m.DeleteAll(); err != nil {
			return err
		}
	}

	if v1BackendMapExistsV4 || v1BackendMapExistsV6 {
		log.Info("Backend map v1 exists. Migrating entries to backend map v2.")
		/*if err := s.populateBackendMapV2FromV1(v1BackendMapExistsV4, v1BackendMapExistsV6); err != nil {
			log.WithError(err).Warn("Error populating V2 map from V1 map, might interrupt existing connections during upgrade")
		}*/
	}

	if cfg.EnableSessionAffinity {
		if _, err := lbmap.AffinityMatchMap.OpenOrCreate(); err != nil {
			return err
		}
		if ipv4 {
			if _, err := lbmap.Affinity4Map.OpenOrCreate(); err != nil {
				return err
			}
		}
		if ipv6 {
			if _, err := lbmap.Affinity6Map.OpenOrCreate(); err != nil {
				return err
			}
		}
	}

	if cfg.EnableSVCSourceRangeCheck {
		if ipv4 {
			if _, err := lbmap.SourceRange4Map.OpenOrCreate(); err != nil {
				return err
			}
		}
		if ipv6 {
			if _, err := lbmap.SourceRange6Map.OpenOrCreate(); err != nil {
				return err
			}
		}
	}

	if cfg.NodePortAlg == serviceConfig.NodePortAlgMaglev {
		maglevTableSize := maglev.DefaultTableSize // FIXME add to ServiceConfig (LBConfig?)
		if err := lbmap.InitMaglevMaps(ipv4, ipv6, uint32(maglevTableSize)); err != nil {
			return fmt.Errorf("initializing maglev maps: %w", err)
		}
	}

	return nil
}
