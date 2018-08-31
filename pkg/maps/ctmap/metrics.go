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
	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/metrics"

	"github.com/sirupsen/logrus"
)

type gcStats struct {
	*bpf.DumpStats

	// aliveEntries is the number of scanned entries that are still alive.
	aliveEntries uint32

	// deleted is the number of keys deleted
	deleted uint32

	// family is the address family
	family gcFamily
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

func statStartGc(m *bpf.Map, family gcFamily) gcStats {
	return gcStats{
		DumpStats: bpf.NewDumpStats(m).Start(),
		family:    family,
	}
}

func (s *gcStats) finish() {
	s.DumpStats.Finish()
	duration := s.Duration()
	family := s.family.String()
	switch s.family {
	case gcFamilyIPv6:
		metrics.DatapathErrors.With(labelIPv6CTDumpInterrupts).Add(float64(s.Interrupted))
	case gcFamilyIPv4:
		metrics.DatapathErrors.With(labelIPv4CTDumpInterrupts).Add(float64(s.Interrupted))
	}

	var status string
	if s.Completed {
		status = "completed"
		metrics.ConntrackGCSize.WithLabelValues(family, metricsAlive).Set(float64(s.aliveEntries))
		metrics.ConntrackGCSize.WithLabelValues(family, metricsDeleted).Set(float64(s.deleted))
	} else {
		status = "uncompleted"
		log.WithField("interrupted", s.Interrupted).Warningf(
			"Garbage collection on IPv6 CT map failed to finish")
	}

	metrics.ConntrackGCRuns.WithLabelValues(family, status).Inc()
	metrics.ConntrackGCDuration.WithLabelValues(family, status).Observe(duration.Seconds())
	metrics.ConntrackGCKeyFallbacks.WithLabelValues(family).Add(float64(s.KeyFallback))

	log.WithFields(logrus.Fields{
		logfields.StartTime: s.Started,
		logfields.Duration:  duration,
		"numDeleted":        s.deleted,
		"numLookups":        s.Lookup,
		"numLookupsFailed":  s.LookupFailed,
		"numKeyFallbacks":   s.KeyFallback,
		"completed":         s.Completed,
		"maxEntries":        s.MaxEntries,
	}).Infof("%s Conntrack garbage collection statistics", s.family)
}
