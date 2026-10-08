// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package xds

import "github.com/cilium/cilium/pkg/lock"

type mockMetrics struct {
	mutex  lock.Mutex
	ack    map[string]int
	nack   map[string]int
	cancel map[string]int
}

func (m *mockMetrics) IncreaseACK(typeURL string) {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	m.ack[typeURL]++
}

func (m *mockMetrics) IncreaseNACK(typeURL string) {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	m.nack[typeURL]++
}

func (m *mockMetrics) IncreaseCancel(typeURL string) {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	m.cancel[typeURL]++
}

func newMockMetrics() *mockMetrics {
	return &mockMetrics{
		ack:    map[string]int{},
		nack:   map[string]int{},
		cancel: map[string]int{},
	}
}
