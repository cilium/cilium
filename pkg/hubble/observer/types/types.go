// Copyright 2020 Authors of Cilium
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

package types

import "time"

const (
	// LostEventSourceUnspec indicates an event has been lost at an unknown
	// source
	LostEventSourceUnspec = iota
	// LostEventSourcePerfRingBuffer indicates an event has been lost because
	// the perf event ring buffer was not read before it was overwritten.
	LostEventSourcePerfRingBuffer
	// LostEventSourceEventsQueue indicates that an event has been dropped
	// because the events queue was full.
	LostEventSourceEventsQueue
	// LostEventSourceHubbleRingBuffer  indicates that an event was dropped
	// because it could not be read from Hubble's ring buffer in time before
	// being overwritten.
	LostEventSourceHubbleRingBuffer
)

// MonitorEvent is the top-level type for all events consumed by the observer
type MonitorEvent struct {
	// Timestamp when the event was received by the consumer
	Timestamp time.Time
	// NodeName where the event occurred
	NodeName string
	// Payload is one of: AgentEvent, PerfEvent or LostEvent
	Payload interface{}
}

// AgentEvent is any agent event
type AgentEvent struct {
	// Type is a monitorAPI.MessageType* value
	Type int
	// Message is the agent message, e.g. accesslog.LogRecord, monitorAPI.AgentNotifyMessage
	Message interface{}
}

// PerfEvent is a raw event obtained from a BPF perf ring buffer
type PerfEvent struct {
	// Data is the raw data payload of the perf event
	Data []byte
	// CPU is the cpu number on which the perf event occurred
	CPU int
}

// LostEvent indicates that a number of events were lost at the indicated source
type LostEvent struct {
	// Source is where the events were dropped
	Source int
	// NumLostEvents is the number of events lost
	NumLostEvents uint64
	// CPU is the cpu number if for events lost in the perf ring buffer
	CPU int
}
