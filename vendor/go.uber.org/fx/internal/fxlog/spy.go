// Copyright (c) 2020-2021 Uber Technologies, Inc.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

package fxlog

import (
	"reflect"

	"go.uber.org/fx/fxevent"
)

// Events is a list of events captured by fxlog.Spy.
type Events []fxevent.Event

// Len returns the number of events in this list.
func (es Events) Len() int { return len(es) }

// SelectByTypeName returns a new list with only events matching the specified
// type.
func (es Events) SelectByTypeName(name string) Events {
	var out Events
	for _, e := range es {
		if reflect.TypeOf(e).Elem().Name() == name {
			out = append(out, e)
		}
	}
	return out
}

// Spy is an Fx event logger that captures emitted events and/or logged
// statements. It may be used in tests of Fx logs.
type Spy struct {
	events Events
}

var _ fxevent.Logger = &Spy{}

// LogEvent appends an Event.
func (s *Spy) LogEvent(event fxevent.Event) {
	s.events = append(s.events, event)
}

// Events returns all captured events.
func (s *Spy) Events() Events {
	events := make(Events, len(s.events))
	copy(events, s.events)
	return events
}

// EventTypes returns all captured event types.
func (s *Spy) EventTypes() []string {
	types := make([]string, len(s.events))
	for i, e := range s.events {
		types[i] = reflect.TypeOf(e).Elem().Name()
	}
	return types
}

// Reset clears all messages and events from the Spy.
func (s *Spy) Reset() {
	s.events = s.events[:0]
}
