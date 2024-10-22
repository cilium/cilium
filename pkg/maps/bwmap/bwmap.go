// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package bwmap

import (
	"fmt"

	"github.com/cilium/hive/cell"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/ebpf"
	"github.com/cilium/cilium/pkg/maps/lxcmap"
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
	Id uint64 `align:"id"`
}

func (k *EdtId) String() string  { return fmt.Sprintf("%d", int(k.Id)) }
func (k *EdtId) New() bpf.MapKey { return &EdtId{} }

type EdtInfo struct {
	Bps             uint64    `align:"bps"`
	TimeLast        uint64    `align:"t_last"`
	TimeHorizonDrop uint64    `align:"t_horizon_drop"`
	Pad             [4]uint64 `align:"pad"`
}

func (v *EdtInfo) String() string    { return fmt.Sprintf("%d", int(v.Bps)) }
func (v *EdtInfo) New() bpf.MapValue { return &EdtInfo{} }

type throttleMap struct {
	*bpf.Map
}

// ThrottleMap constructs the cilium_throttle map. Direct use of this
// outside of this package is solely for cilium-dbg.
func ThrottleMap() *bpf.Map {
	return bpf.NewMap(
		MapName,
		ebpf.Hash,
		&EdtId{},
		&EdtInfo{},
		MapSize,
		bpf.BPF_F_NO_PREALLOC,
	)
}

func newThrottleMap(cfg types.BandwidthConfig, lc cell.Lifecycle) (out bpf.MapOut[throttleMap]) {
	m := throttleMap{ThrottleMap()}
	if cfg.EnableBandwidthManager {
		// Only open the map if bandwidth manager is enabled.
		lc.Append(cell.Hook{
			OnStart: func(cell.HookContext) error {
				return m.OpenOrCreate()
			},
			OnStop: func(cell.HookContext) error {
				return m.Close()
			},
		})
	}
	return bpf.NewMapOut(m)
}
