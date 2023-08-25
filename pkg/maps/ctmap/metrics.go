// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ctmap

import (
	"fmt"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/maps/nat"
	"github.com/cilium/cilium/pkg/metrics"
)

type gcStats struct {
	*bpf.DumpStats

	// aliveEntries is the number of scanned entries that are still alive.
	aliveEntries uint32

	// deleted is the number of keys deleted
	deleted uint32

	// family is the address family
	family gcFamily

	// proto is the L4 protocol
	proto gcProtocol

	// dumpError records any error that occurred during the dump.
	dumpError error
}

type gcFamily int

const (
	gcFamilyIPv4 gcFamily = iota
	gcFamilyIPv6
)

func (g gcFamily) String() string {
	switch g {
	case gcFamilyIPv4:
		return "ipv4"
	case gcFamilyIPv6:
		return "ipv6"
	default:
		return "unknown"
	}
}

type gcProtocol int

const (
	gcProtocolAny gcProtocol = iota
	gcProtocolTCP
)

func (g gcProtocol) String() string {
	switch g {
	case gcProtocolAny:
		return "non-TCP"
	case gcProtocolTCP:
		return "TCP"
	default:
		return fmt.Sprintf("unknown (%d)", int(g))
	}
}

func statStartGc(m *Map) gcStats {
	result := gcStats{
		DumpStats: bpf.NewDumpStats(&m.Map),
	}
	if m.mapType.isIPv6() {
		result.family = gcFamilyIPv6
	} else {
		result.family = gcFamilyIPv4
	}
	if m.mapType.isTCP() {
		result.proto = gcProtocolTCP
	} else {
		result.proto = gcProtocolAny
	}
	return result
}

func (s *gcStats) finish() {
	duration := s.Duration()
	family := s.family.String()
	switch s.family {
	case gcFamilyIPv6:
		metrics.ConntrackDumpResets.With(labelIPv6CTDumpInterrupts).Add(float64(s.Interrupted))
	case gcFamilyIPv4:
		metrics.ConntrackDumpResets.With(labelIPv4CTDumpInterrupts).Add(float64(s.Interrupted))
	}
	proto := s.proto.String()

	var status string
	if s.Completed {
		status = "completed"
		metrics.ConntrackGCSize.WithLabelValues(family, proto, metricsAlive).Set(float64(s.aliveEntries))
		metrics.ConntrackGCSize.WithLabelValues(family, proto, metricsDeleted).Set(float64(s.deleted))
	} else {
		status = "uncompleted"
		scopedLog := log.WithField("interrupted", s.Interrupted)
		if s.dumpError != nil {
			scopedLog = scopedLog.WithError(s.dumpError)
		}
		scopedLog.Warningf("Garbage collection on %s %s CT map failed to finish", family, proto)
	}

	metrics.ConntrackGCRuns.WithLabelValues(family, proto, status).Inc()
	metrics.ConntrackGCDuration.WithLabelValues(family, proto, status).Observe(duration.Seconds())
	metrics.ConntrackGCKeyFallbacks.WithLabelValues(family, proto).Add(float64(s.KeyFallback))
}

type NatGCStats struct {
	*bpf.DumpStats

	// family is the address family
	Family gcFamily

	IngressAlive   uint32
	IngressDeleted uint32
	EgressDeleted  uint32
	EgressAlive    uint32
}

func newNatGCStats(m *nat.Map, family gcFamily) NatGCStats {
	return NatGCStats{
		DumpStats: m.DumpStats(),
		Family:    family,
	}
}

func (s *NatGCStats) finish() {
	family := s.Family.String()
	metrics.NatGCSize.WithLabelValues(family, metricsIngress, metricsAlive).Set(float64(s.IngressAlive))
	metrics.NatGCSize.WithLabelValues(family, metricsIngress, metricsDeleted).Set(float64(s.IngressDeleted))
	metrics.NatGCSize.WithLabelValues(family, metricsEgress, metricsAlive).Set(float64(s.EgressAlive))
	metrics.NatGCSize.WithLabelValues(family, metricsEgress, metricsDeleted).Set(float64(s.EgressDeleted))
}
