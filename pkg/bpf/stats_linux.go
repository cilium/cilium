// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build linux

package bpf

import (
	"time"
)

// DumpStats tracks statistics over the dump of a map.
type DumpStats struct {
	// Started is the timestamp when the gc run was started.
	Started time.Time

	// Finished is the timestamp when the gc run completed.
	Finished time.Time

	// Lookup is the number of key lookups performed.
	Lookup uint32

	// LookupFailed is the number of key lookups that failed.
	LookupFailed uint32

	// PrevKeyUnavailable is the number of times the previous key was not
	// available.
	PrevKeyUnavailable uint32

	// KeyFallback is the number of times the current key became invalid
	// while traversing and we had to fall back to the previous key.
	KeyFallback uint32

	// MaxEntries is the maximum number of entries in the gc table.
	MaxEntries uint32

	// Interrupted is the number of times the gc run was interrupted and
	// had to start from scratch.
	Interrupted uint32

	// Completed is true when the gc run has been completed.
	Completed bool
}

// NewDumpStats returns a new stats structure for collecting dump statistics.
func NewDumpStats(m *Map) *DumpStats {
	return &DumpStats{
		MaxEntries: m.MapInfo.MaxEntries,
	}
}

// start starts the dump.
func (d *DumpStats) start() {
	d.Started = time.Now()
}

// finish finishes the dump.
func (d *DumpStats) finish() {
	d.Finished = time.Now()
}

// Duration returns the duration of the dump.
func (d *DumpStats) Duration() time.Duration {
	return d.Finished.Sub(d.Started)
}
