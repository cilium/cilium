// Copyright 2016-2018 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package ctmap

import (
	"fmt"

	"github.com/cilium/cilium/pkg/bpf"
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
	gcFamilyIPv4 = iota
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
	gcProtocolAny = iota
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
		metrics.DatapathErrors.With(labelIPv6CTDumpInterrupts).Add(float64(s.Interrupted))
	case gcFamilyIPv4:
		metrics.DatapathErrors.With(labelIPv4CTDumpInterrupts).Add(float64(s.Interrupted))
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

	IngressAlive   uint32
	IngressDeleted uint32
	EgressDeleted  uint32
	// It's not possible with the current PurgeOrphanNATEntries implementation
	// to correctly count EgressAlive, so skip it
}

func newNatGCStats(m NatMap) NatGCStats {
	return NatGCStats{
		DumpStats: m.DumpStats(),
	}
}
