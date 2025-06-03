// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package lbmap

import (
	"golang.org/x/sys/unix"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/byteorder"
	"github.com/cilium/cilium/pkg/cidr"
	"github.com/cilium/cilium/pkg/ebpf"
	"github.com/cilium/cilium/pkg/loadbalancer/maps"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/option"
)

const (
	SourceRange4MapName = maps.SourceRange4MapName
	SourceRange6MapName = maps.SourceRange6MapName
	lpmPrefixLen4       = 16 + 16 // sizeof(SourceRangeKey4.RevNATID)+sizeof(SourceRangeKey4.Pad)
	lpmPrefixLen6       = 16 + 16 // sizeof(SourceRangeKey6.RevNATID)+sizeof(SourceRangeKey6.Pad)
)

type (
	SourceRangeKey = maps.SourceRangeKey

	SourceRangeKey4 = maps.SourceRangeKey4
	SourceRangeKey6 = maps.SourceRangeKey6

	SourceRangeValue = maps.SourceRangeValue
)

var (
	// SourceRange4Map is the BPF map for storing IPv4 service source ranges to
	// check if option.Config.EnableSVCSourceRangeCheck is enabled.
	SourceRange4Map *bpf.Map
	// SourceRange6Map is the BPF map for storing IPv6 service source ranges to
	// check if option.Config.EnableSVCSourceRangeCheck is enabled.
	SourceRange6Map *bpf.Map
)

// initSourceRange creates the BPF maps for storing both IPv4 and IPv6
// service source ranges.
func initSourceRange(registry *metrics.Registry, params InitParams) {
	SourceRangeMapMaxEntries = params.SourceRangeMapMaxEntries

	if params.IPv4 {
		SourceRange4Map = bpf.NewMap(
			SourceRange4MapName,
			ebpf.LPMTrie,
			&SourceRangeKey4{},
			&SourceRangeValue{},
			SourceRangeMapMaxEntries,
			unix.BPF_F_NO_PREALLOC,
		).WithCache().WithPressureMetric(registry).
			WithEvents(option.Config.GetEventBufferConfig(SourceRange4MapName))
	}

	if params.IPv6 {
		SourceRange6Map = bpf.NewMap(
			SourceRange6MapName,
			ebpf.LPMTrie,
			&SourceRangeKey6{},
			&SourceRangeValue{},
			SourceRangeMapMaxEntries,
			unix.BPF_F_NO_PREALLOC,
		).WithCache().WithPressureMetric(registry).
			WithEvents(option.Config.GetEventBufferConfig(SourceRange6MapName))
	}
}

func srcRangeKey(cidr *cidr.CIDR, revNATID uint16, ipv6 bool) bpf.MapKey {
	ones, _ := cidr.Mask.Size()
	id := byteorder.HostToNetwork16(revNATID)
	if ipv6 {
		key := &SourceRangeKey6{PrefixLen: uint32(ones) + lpmPrefixLen6, RevNATID: id}
		copy(key.Address[:], cidr.IP.To16())
		return key
	} else {
		key := &SourceRangeKey4{PrefixLen: uint32(ones) + lpmPrefixLen4, RevNATID: id}
		copy(key.Address[:], cidr.IP.To4())
		return key
	}
}
