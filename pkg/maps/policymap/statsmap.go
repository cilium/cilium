// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package policymap

import (
	"errors"
	"fmt"
	"log/slog"
	"math"
	"strconv"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/byteorder"
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
	nCPU = ebpf.MustPossibleCPU()
)

// PolicyStatsMap maps endpoint IDs to the fd for the program which
// implements its policy.
type StatsMap struct {
	*bpf.Map
	log *slog.Logger
}

func newStatsMap(maxStatsEntries int, log *slog.Logger) *StatsMap {
	roundDown := maxStatsEntries % nCPU
	maxStatsEntries -= roundDown

	if log == nil {
		log = slog.Default()
	}

	// Must return a valid map even if returning an error
	return &StatsMap{
		Map: bpf.NewMap(
			StatsMapName,
			ebpf.LRUCPUHash,
			&StatsKey{},
			StatsValues{},
			maxStatsEntries,
			bpf.BPF_F_NO_COMMON_LRU,
		),
		log: log,
	}
}

// OpenStatsMap opens the global policy stats map for reading.
func OpenStatsMap() (*StatsMap, error) {
	m := newStatsMap(1024, nil)
	err := m.Open()
	return m, err
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
	dir := "ingress"
	if k.TrafficDirection != 0 {
		dir = "egress"
	}
	return fmt.Sprintf("%d %s %d %d %d %d", k.EpID, dir, k.Identity, k.Nexthdr,
		byteorder.NetworkToHost16(k.DestPortNetwork), k.PrefixLen)
}

func (k *StatsKey) New() bpf.MapKey { return &StatsKey{} }

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

func (v StatsValues) String() string    { return "" }
func (k StatsValues) New() bpf.MapValue { return make(StatsValues, nCPU) }

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

	v, err := m.Lookup(&statsKey)
	if err == nil {
		values := v.(StatsValues)
		for _, v := range values {
			packets += v.Packets
			bytes += v.Bytes
		}
		return packets, bytes
	}

	if !errors.Is(err, unix.ENOENT) {
		m.log.Warn("Error getting policy stats", "error", err, logfields.BPFMapKey, statsKey)
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

	m.log.Warn("Error deleting policy stats", "error", err, logfields.BPFMapKey, statsKey)
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

	err := m.Update(&statsKey, zeroValue)

	if err != nil {
		m.log.Warn("Error zeroing policy stats", "error", err, logfields.BPFMapKey, statsKey)
	}
	return err
}
