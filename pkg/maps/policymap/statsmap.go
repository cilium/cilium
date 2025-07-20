// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package policymap

import (
	"errors"
	"log/slog"
	"math"
	"strconv"
	"unsafe"

	ciliumebpf "github.com/cilium/ebpf"
	"golang.org/x/sys/unix"

	"github.com/cilium/cilium/pkg/ebpf"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

const (
	// Name is the canonical name for the policy stats map on the filesystem.
	// Note: There is no underscore between 'policy' and 'stats' as that would confuse tools
	// trying to parse an endpoint ID from 'stats'.
	StatsMapName = "cilium_policystats"

	StatNotAvailable = uint64(math.MaxUint64)
)

var (
	// nCPU must be on package level to be available for StatsValues.New() below
	nCPU = ciliumebpf.MustPossibleCPU()
)

// PolicyStatsMap maps endpoint IDs to the fd for the program which
// implements its policy.
type StatsMap struct {
	*ebpf.Map
	log *slog.Logger
}

func newStatsMap(maxStatsEntries int, log *slog.Logger) (*StatsMap, int) {
	roundDown := maxStatsEntries % nCPU
	maxStatsEntries -= roundDown

	// Must return a valid map even if returning an error
	return &StatsMap{
		Map: ebpf.NewMap(log, &ebpf.MapSpec{
			Name:       StatsMapName,
			Type:       ebpf.LRUCPUHash,
			KeySize:    uint32(unsafe.Sizeof(StatsKey{})),
			ValueSize:  uint32(unsafe.Sizeof(StatsValue{})),
			MaxEntries: uint32(maxStatsEntries),
			Flags:      unix.BPF_F_NO_COMMON_LRU,
			Pinning:    ebpf.PinByName,
		}),
		log: log,
	}, maxStatsEntries
}

// OpenStatsMap opens the existing global policy stats map.
// Should only be called from cilium-dbg
func OpenStatsMap(logger *slog.Logger) (*StatsMap, error) {
	m, err := ebpf.LoadRegisterMap(logger, StatsMapName)
	if err != nil {
		return nil, err
	}
	return &StatsMap{
		Map: m,
		log: logger,
	}, nil
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

type StatsValue struct {
	Packets uint64 `align:"packets"`
	Bytes   uint64 `align:"bytes"`
}

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
	var values StatsValues
	err := m.Lookup(&statsKey, &values)
	if err == nil {
		for _, v := range values {
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
	zeroValue := make(StatsValues, nCPU)

	err := m.Update(&statsKey, zeroValue, 0)

	if err != nil {
		m.log.Warn("Error zeroing policy stats",
			logfields.Error, err,
			logfields.BPFMapKey, statsKey)
	}
	return err
}
