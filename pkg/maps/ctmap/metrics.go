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
	"time"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/metrics"

	"github.com/sirupsen/logrus"
)

type gcStats struct {
	// started is the timestamp when the gc run was started
	started time.Time

	// finishedis the timestamp when the gc run completed
	finished time.Time

	// lookup is the number of key lookups performed
	lookup uint32

	// lookupFailed is the number of key lookups that failed
	lookupFailed uint32

	// prevKeyUnavailable is the number of times the previous key was not
	// available
	prevKeyUnavailable uint32

	// deleted is the number of keys deleted
	deleted uint32

	// keyFallback is the number of times the current key became invalid
	// while traversing and we had to fall back to the previous key
	keyFallback uint32

	// count is number of lookups performed on the map
	count uint32

	// maxEntries is the maximum number of entries in the gc table
	maxEntries uint32

	// family is the address family
	family gcFamily

	// completed is true when the gc run has been completed
	completed bool

	// interrupted is the number of times the gc run was interrupted and
	// had to start from scratch
	interrupted uint32

	// aliveEntries is the number of scanned entries that are still alive
	aliveEntries uint32
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
		started:    time.Now(),
		count:      1,
		maxEntries: m.MapInfo.MaxEntries,
		family:     family,
	}
}

func (s *gcStats) finish() {
	s.finished = time.Now()
	duration := s.finished.Sub(s.started)
	family := s.family.String()
	switch s.family {
	case gcFamilyIPv6:
		metrics.DatapathErrors.With(labelIPv6CTDumpInterrupts).Add(float64(s.interrupted))
	case gcFamilyIPv4:
		metrics.DatapathErrors.With(labelIPv4CTDumpInterrupts).Add(float64(s.interrupted))
	}

	var status string
	if s.completed {
		status = "completed"
		metrics.ConntrackGCSize.WithLabelValues(family, metricsAlive).Set(float64(s.aliveEntries))
		metrics.ConntrackGCSize.WithLabelValues(family, metricsDeleted).Set(float64(s.deleted))
	} else {
		status = "uncompleted"
		log.WithField("interrupted", s.interrupted).Warningf(
			"Garbage collection on IPv6 CT map failed to finish")
	}

	metrics.ConntrackGCRuns.WithLabelValues(family, status).Inc()
	metrics.ConntrackGCDuration.WithLabelValues(family, status).Observe(duration.Seconds())
	metrics.ConntrackGCKeyFallbacks.WithLabelValues(family).Add(float64(s.keyFallback))

	log.WithFields(logrus.Fields{
		logfields.StartTime: s.started,
		logfields.Duration:  duration,
		"numDeleted":        s.deleted,
		"numLookups":        s.count,
		"numLookupsFailed":  s.lookupFailed,
		"numKeyFallbacks":   s.keyFallback,
		"completed":         s.completed,
		"maxEntries":        s.maxEntries,
	}).Infof("%s Conntrack garbage collection statistics", s.family)
}
