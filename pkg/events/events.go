// Copyright 2016-2017 Authors of Cilium
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

package events

import (
	"time"
)

const (
	// IdentityAdd is the event type used when a new identity is added to
	// the K/V store.
	IdentityAdd EventType = iota
	// IdentityMod is the event type used when a existing identity is
	// scheduled for deletion but there are still reference counts to it.
	IdentityMod
	// IdentityDel is the event type used when a existing identity is
	// deleted.
	IdentityDel
)

// EventType represents the type of event that occurred.
type EventType int

// Event is used to trigger events throughout the daemon.
type Event struct {
	Type      EventType
	Timestamp time.Time
	Obj       interface{}
}

// NewEvent creates a new event from type and interface.
func NewEvent(t EventType, obj interface{}) *Event {
	return &Event{
		Type:      t,
		Timestamp: time.Now(),
		Obj:       obj,
	}
}
