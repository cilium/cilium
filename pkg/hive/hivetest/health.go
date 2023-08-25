// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package hivetest

import "github.com/cilium/cilium/pkg/lock"

// MockHealthReporter is a mock implementation of cell.HealthReporter type.
// It provides a minimal implementation that can notify on events via an unbuffered channel.
// Further updates will block until all events are observed.
//
// Empty initialization provides an implementation that is a no-op and will not
// notify on any updates.
type MockHealthReporter struct {
	lock.Mutex
	notify chan Update
}

// NewMockHealthReporter creates a new mock health reporter which will block until
// the event is consumed on the Wait channel.
func NewMockHealthReporter() *MockHealthReporter {
	return &MockHealthReporter{
		notify: make(chan Update),
	}
}

// Update is a single update to the health status. We don't use the cell.Update
// type as it contains other fields that are not relevant to the test fixture.
type Update struct {
	Event string
	Err   error
}

// OK updates with OK status.
func (m *MockHealthReporter) OK(msg string) {
	m.Lock()
	defer m.Unlock()
	if m.notify == nil {
		return
	}
	m.notify <- Update{Event: "OK"}
}

// Degraded updates with Degraded status.
func (m *MockHealthReporter) Degraded(msg string, err error) {
	m.Lock()
	defer m.Unlock()
	if m.notify == nil {
		return
	}
	m.notify <- Update{Event: "Degraded", Err: err}
}

// Degraded updates with Stopped status, but will not actually
// stop the test reporter.
func (m *MockHealthReporter) Stopped(msg string) {
	m.Lock()
	defer m.Unlock()
	if m.notify == nil {
		return
	}
	m.notify <- Update{Event: "Stopped"}
}

// Wait returns a channel that will receive updates on the health status.
func (m *MockHealthReporter) Wait() <-chan Update {
	return m.notify
}
