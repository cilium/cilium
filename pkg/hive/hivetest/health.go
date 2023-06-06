// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package hivetest

import "github.com/cilium/cilium/pkg/lock"

type MockHealthReporter struct {
	lock.Mutex
	m       string
	stopped bool
	err     error
}

func (m *MockHealthReporter) Msg() string {
	m.Lock()
	defer m.Unlock()
	return m.m
}

func (m *MockHealthReporter) Err() error {
	m.Lock()
	defer m.Unlock()
	return m.err
}

func (m *MockHealthReporter) IsStopped() bool {
	m.Lock()
	defer m.Unlock()
	return m.stopped
}

func (m *MockHealthReporter) OK(msg string) {
	m.Lock()
	defer m.Unlock()
	m.m = msg
	m.err = nil
}

func (m *MockHealthReporter) Degraded(msg string, err error) {
	m.Lock()
	defer m.Unlock()
	m.m = msg
	m.err = err
}

func (m *MockHealthReporter) Stopped(msg string) {
	m.Lock()
	defer m.Unlock()
	m.m = msg
	m.stopped = true
}
