// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ibwmap

import (
	"fmt"

	"github.com/cilium/hive/cell"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/ebpf"
	"github.com/cilium/cilium/pkg/maps/lxcmap"
)

const (
	MapName = "cilium_ingress_throttle"
	// Flow aggregate is per Pod, so same size as Endpoint map.
	MapSize = lxcmap.MaxEntries
)

type ThrottleID struct {
	Id uint64 `align:"id"`
}

func (k *ThrottleID) String() string  { return fmt.Sprintf("%d", int(k.Id)) }
func (k *ThrottleID) New() bpf.MapKey { return &ThrottleID{} }

type ThrottleInfo struct {
	Bps      uint64    `align:"bps"`
	TimeLast uint64    `align:"t_last"`
	Tokens   uint64    `align:"tokens"`
	Pad      [4]uint64 `align:"pad"`
}

func (v *ThrottleInfo) String() string    { return fmt.Sprintf("%d", int(v.Bps)) }
func (v *ThrottleInfo) New() bpf.MapValue { return &ThrottleInfo{} }

type throttleMap struct {
	*bpf.Map
}

// ThrottleMap constructs the cilium_ingress_throttle map. Direct use of this
// outside of this package is solely for cilium-dbg.
func ThrottleMap() *bpf.Map {
	return bpf.NewMap(
		MapName,
		ebpf.Hash,
		&ThrottleID{},
		&ThrottleInfo{},
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
