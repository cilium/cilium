// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package policymap

import (
	"errors"
	"fmt"

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
)

var (
	// MaxEntries is the maximum number of keys that can be present in the
	// policy stats map.
	// This number is rounded down to the closest multiple of 'ebpf.PossibleCPU()' to avoid map
	// size mismatch and endless repinning due to a size mismatch.
	MaxStatsEntries = 65536
)

// PolicyStatsMap maps endpoint IDs to the fd for the program which
// implements its policy.
type StatsMap struct {
	bpf.Map
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

func (k *StatsKey) String() string {
	dir := "ingress"
	if k.TrafficDirection != 0 {
		dir = "egress"
	}
	return fmt.Sprintf("%d %s %d %d %d %d", k.EpID, dir, k.Identity, k.Nexthdr,
		byteorder.NetworkToHost16(k.DestPortNetwork), k.PrefixLen)
}

func (k *StatsKey) New() bpf.MapKey { return &StatsKey{} }

func (v *StatsValue) String() string {
	return fmt.Sprintf("%d %d", v.Packets, v.Bytes)
}

// StatsMap is a per-CPU map, so the value is a slice
type StatsValues []StatsValue

// String returns an empty string as the per-CPU values are summed together into a StatsValue
func (v *StatsValues) String() string {
	return ""
}
func (k *StatsValues) New() bpf.MapValue { return &StatsValues{} }
func (k *StatsValues) NewSlice() any     { return &StatsValues{} }

func newStatsMap() *StatsMap {
	return &StatsMap{
		Map: *bpf.NewMap(
			StatsMapName,
			ebpf.LRUCPUHash,
			&StatsKey{},
			&StatsValues{},
			MaxStatsEntries,
			bpf.BPF_F_NO_COMMON_LRU,
		),
	}
}

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
		for _, v := range *v.(*StatsValues) {
			packets += v.Packets
			bytes += v.Bytes
		}
	} else if !errors.Is(err, unix.ENOENT) {
		log.WithError(err).
			WithField(logfields.BPFMapKey, statsKey.String()).
			Warning("Error looking policy stats")
	}
	return packets, bytes
}

// ClearStat looks up stats for the given endpoint and policy key
func (m *StatsMap) ClearStat(epID uint16, k PolicyKey) {
	statsKey := StatsKey{
		EpID:             epID,
		PrefixLen:        k.GetPrefixLen(),
		Identity:         k.Identity,
		TrafficDirection: k.TrafficDirection,
		Nexthdr:          k.Nexthdr,
		DestPortNetwork:  k.DestPortNetwork,
	}
	err := m.Delete(&statsKey)
	if err != nil && !errors.Is(err, unix.ENOENT) {
		log.WithError(err).
			WithField(logfields.BPFMapKey, &statsKey).
			Warning("Error deleting policy stats")
	}
}

// CreateStatsMap opens an existing stats map or creates a new one if one does not already exist
func CreateStatsMap() error {
	m := newStatsMap()
	return m.OpenOrCreate()
}

// OpenStatsMap opens the global policy stats map.
func OpenStatsMap() (*StatsMap, error) {
	m := newStatsMap()
	err := m.Open()
	if err != nil {
		return nil, err
	}
	return m, nil
}
