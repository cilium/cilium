// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package bwmap

import (
	"fmt"
	"sync"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/ebpf"
	"github.com/cilium/cilium/pkg/maps/lxcmap"
	"github.com/cilium/cilium/pkg/option"
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

var (
	throttleMap     *bpf.Map
	throttleMapInit = &sync.Once{}
)

func ThrottleMap() *bpf.Map {
	throttleMapInit.Do(func() {
		throttleMap = bpf.NewMap(
			MapName,
			ebpf.Hash,
			&EdtId{},
			&EdtInfo{},
			MapSize,
			bpf.BPF_F_NO_PREALLOC,
		).WithCache().WithPressureMetric().
			WithEvents(option.Config.GetEventBufferConfig(MapName))
	})

	return throttleMap
}

func Update(Id uint16, Bps uint64) error {
	return ThrottleMap().Update(
		&EdtId{Id: uint64(Id)},
		&EdtInfo{Bps: Bps, TimeHorizonDrop: uint64(DefaultDropHorizon)})
}

func Delete(Id uint16) error {
	return ThrottleMap().Delete(
		&EdtId{Id: uint64(Id)})
}

func SilentDelete(Id uint16) error {
	_, err := ThrottleMap().SilentDelete(
		&EdtId{Id: uint64(Id)})

	return err
}
