// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package bwmap

import (
	"fmt"
	"log/slog"
	"strings"

	"github.com/cilium/hive/cell"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/ebpf"
	"github.com/cilium/cilium/pkg/maps/lxcmap"
	"github.com/cilium/cilium/pkg/maps/registry"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/time"
)

const (
	MapName = "cilium_throttle"
	// Flow aggregate is per Pod, so same size as Endpoint map.
	MapSize = lxcmap.MaxEntries

	// DefaultDropHorizon represents maximum allowed departure
	// time delta in future. Given applications can set SO_TXTIME
	// from user space this is a limit to prevent buggy applications
	// to fill the FQ qdisc.
	DefaultDropHorizon = 2 * time.Second
)

type EdtId struct {
	Id        uint32   `align:"id"`
	Direction uint8    `align:"direction"`
	Pad       [3]uint8 `align:"pad"`
}

func (k *EdtId) String() string {
	return fmt.Sprintf("%d, %d", int(k.Id), int(k.Direction))
}

func (k *EdtId) New() bpf.MapKey { return &EdtId{} }

type EdtInfo struct {
	Bps                     uint64    `align:"bps"`
	TimeLast                uint64    `align:"t_last"`
	TimeHorizonDropOrTokens uint64    `align:"$union0"`
	Prio                    uint32    `align:"prio"`
	Pad32                   uint32    `align:"pad_32"`
	Pad                     [3]uint64 `align:"pad"`
}

func (v *EdtInfo) String() string {
	return fmt.Sprintf("%d, %d", int(v.Bps), int(v.Prio))
}

func (v *EdtInfo) New() bpf.MapValue { return &EdtInfo{} }

type throttleMap struct {
	m *bpf.Map
}

func (tm *throttleMap) IsOpen() bool {
	if tm.m == nil {
		return false
	}

	return tm.m.IsOpen()
}

func (tm *throttleMap) NonPrefixedName() string {
	return strings.TrimPrefix(MapName, metrics.Namespace+"_")
}

func (tm *throttleMap) MaxEntries() uint32 {
	if tm.m == nil {
		return 0
	}

	return tm.m.MaxEntries()
}

// ThrottleMap opens an already initialized cilium_throttle map. Direct use of this
// outside of this package is solely for cilium-dbg.
func ThrottleMap(logger *slog.Logger) (*bpf.Map, error) {
	return bpf.OpenMap(bpf.MapPath(logger, MapName), &EdtId{}, &EdtInfo{})
}

func newThrottleMap(lc cell.Lifecycle, cfg types.BandwidthConfig, specReg *registry.MapSpecRegistry) (out bpf.MapOut[*throttleMap], err error) {
	m := &throttleMap{}

	err = specReg.Modify(MapName, func(spec *ebpf.MapSpec) error {
		spec.MaxEntries = uint32(MapSize)
		return nil
	})
	if err != nil {
		return bpf.MapOut[*throttleMap]{}, err
	}

	if cfg.EnableBandwidthManager {
		// Only open the map if bandwidth manager is enabled.
		lc.Append(cell.Hook{
			OnStart: func(cell.HookContext) error {
				var err error

				m.m, err = specReg.NewMap(MapName, &EdtId{}, &EdtInfo{})
				if err != nil {
					return err
				}

				return m.m.OpenOrCreate()
			},
			OnStop: func(cell.HookContext) error {
				return m.m.Close()
			},
		})
	}

	return bpf.NewMapOut(m), nil
}
