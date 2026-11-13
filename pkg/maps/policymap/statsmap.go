// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package policymap

import (
	"errors"
	"fmt"
	"log/slog"
	"math"
	"strconv"

	ciliumebpf "github.com/cilium/ebpf"
	"github.com/cilium/hive/cell"
	"golang.org/x/sys/unix"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/datapath/maps"
	"github.com/cilium/cilium/pkg/logging/logfields"
	mapregistry "github.com/cilium/cilium/pkg/maps/registry"
)

const StatNotAvailable = uint64(math.MaxUint64)

// PolicyStatsMap maps endpoint IDs to the fd for the program which
// implements its policy.
type StatsMap struct {
	*bpf.Map
	log *slog.Logger
}

func newStatsMap(
	lc cell.Lifecycle,
	reg *mapregistry.MapRegistry,
	log *slog.Logger,
) bpf.MapOut[*StatsMap] {
	statsMap := &StatsMap{
		log: log,
	}
	lc.Append(cell.Hook{
		OnStart: func(hc cell.HookContext) error {
			var err error
			statsMap.Map, err = bpf.NewMapFromRegistry(reg, maps.CiliumPolicystats, &StatsKey{}, &StatsValue{})
			if err != nil {
				return fmt.Errorf("create policy stats map from registry: %w", err)
			}
			return statsMap.OpenOrCreate()
		},
		OnStop: func(cell.HookContext) error {
			return statsMap.Close()
		},
	})

	return bpf.NewMapOut(statsMap)
}

// OpenStatsMap opens the existing global policy stats map.
// Should only be called from cilium-dbg
func OpenStatsMap(logger *slog.Logger) (*StatsMap, error) {
	m, err := bpf.OpenMap(bpf.MapPath(logger, maps.CiliumPolicystats), &StatsKey{}, &StatsValue{})
	if err != nil {
		return nil, err
	}
	return &StatsMap{log: logger, Map: m}, nil
}

func possibleCPU(logger *slog.Logger) int {
	nCPU, err := ciliumebpf.PossibleCPU()
	if err != nil {
		logger.Error("Failed to determine possible CPUs", logfields.Error, err)
		// Fallback to 1 CPU if we cannot determine the number of CPUs
		return 1
	}
	return nCPU
}

type StatsKey struct {
	EpID             uint16 `align:"endpoint_id"`
	Pad1             uint8  `align:"pad1"`
	PrefixLen        uint8  `align:"prefix_len"`
	Identity         uint32 `align:"sec_label"`
	TrafficDirection uint8  `align:"egress"`
	Nexthdr          uint8  `align:"protocol"`
	DestPortNetwork  uint16 `align:"dport"` // In network byte-order
}

func (k *StatsKey) String() string {
	return fmt.Sprintf("%d %d %d %d %d %d", k.EpID, k.PrefixLen, k.Identity,
		k.TrafficDirection, k.Nexthdr, k.DestPortNetwork)
}

func (k *StatsKey) New() bpf.MapKey { return &StatsKey{} }

type StatsValue struct {
	Packets uint64 `align:"packets"`
	Bytes   uint64 `align:"bytes"`
}

func (v *StatsValue) New() bpf.MapValue { return &StatsValue{} }

func (v *StatsValue) NewSlice() any { return &StatsValues{} }

func (v *StatsValue) String() string {
	bb := make([]byte, 0, 20)

	if v.Packets == StatNotAvailable {
		bb = append(bb, '-')
	} else {
		bb = strconv.AppendUint(bb, v.Packets, 10)
	}
	bb = append(bb, ' ')
	if v.Bytes == StatNotAvailable {
		bb = append(bb, '-')
	} else {
		bb = strconv.AppendUint(bb, v.Bytes, 10)
	}
	return string(bb)
}

// StatsMap is a per-CPU map, so the value is a slice
type StatsValues []StatsValue

func (vs StatsValues) String() string { return fmt.Sprint([]StatsValue(vs)) }

func (vs StatsValues) New() bpf.MapValue { return StatsValues{} }

// GetStat looks up stats for the given endpoint and policy key
func (m *StatsMap) GetStat(epID uint16, k PolicyKey) (packets, bytes uint64) {
	statsKey := StatsKey{
		EpID:             epID,
		PrefixLen:        k.GetPrefixLen(),
		Identity:         k.Identity,
		TrafficDirection: k.TrafficDirection,
		Nexthdr:          k.Nexthdr,
		DestPortNetwork:  k.DestPortNetwork,
	}
	value, err := m.Lookup(&statsKey)
	if err == nil {
		for _, v := range *value.(*StatsValues) {
			packets += v.Packets
			bytes += v.Bytes
		}
		return packets, bytes
	}

	if !errors.Is(err, unix.ENOENT) {
		m.log.Warn("Error getting policy stats",
			logfields.Error, err,
			logfields.BPFMapKey, statsKey)
	}
	return StatNotAvailable, StatNotAvailable
}

// ClearStat removes stats for the given endpoint and policy key
func (m *StatsMap) ClearStat(epID uint16, k PolicyKey) error {
	statsKey := StatsKey{
		EpID:             epID,
		PrefixLen:        k.GetPrefixLen(),
		Identity:         k.Identity,
		TrafficDirection: k.TrafficDirection,
		Nexthdr:          k.Nexthdr,
		DestPortNetwork:  k.DestPortNetwork,
	}

	err := m.Delete(&statsKey)

	if err == nil || errors.Is(err, unix.ENOENT) {
		return nil
	}

	m.log.Warn("Error deleting policy stats",
		logfields.Error, err,
		logfields.BPFMapKey, statsKey)
	return err
}

// ZeroStat updates stats to "0,0" for the given endpoint and policy key
func (m *StatsMap) ZeroStat(epID uint16, k PolicyKey) error {
	statsKey := StatsKey{
		EpID:             epID,
		PrefixLen:        k.GetPrefixLen(),
		Identity:         k.Identity,
		TrafficDirection: k.TrafficDirection,
		Nexthdr:          k.Nexthdr,
		DestPortNetwork:  k.DestPortNetwork,
	}
	nCPU := possibleCPU(m.log)
	zeroValue := make(StatsValues, nCPU)

	err := m.Update(&statsKey, zeroValue)

	if err != nil {
		m.log.Warn("Error zeroing policy stats",
			logfields.Error, err,
			logfields.BPFMapKey, statsKey)
	}
	return err
}
