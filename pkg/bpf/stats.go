// Copyright 2018 Authors of Cilium
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
		Lookup:     1,
		MaxEntries: m.MapInfo.MaxEntries,
	}
}

// Start starts the dump.
//
// For convenience, it returns a pointer to itself.
func (d *DumpStats) Start() *DumpStats {
	d.Started = time.Now()
	return d
}

// Finish finishes the dump.
func (d *DumpStats) Finish() {
	d.Finished = time.Now()
}

// Duration returns the duration of the dump.
func (d *DumpStats) Duration() time.Duration {
	return d.Finished.Sub(d.Started)
}
