// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package xds

type mockMetrics struct {
	ack    map[string]int
	nack   map[string]int
	cancel map[string]int
}

func (m *mockMetrics) IncreaseACK(typeURL string) {
	m.ack[typeURL]++
}

func (m *mockMetrics) IncreaseNACK(typeURL string) {
	m.nack[typeURL]++
}

func (m *mockMetrics) IncreaseCancel(typeURL string) {
	m.cancel[typeURL]++
}

func newMockMetrics() *mockMetrics {
	return &mockMetrics{
		ack:    map[string]int{},
		nack:   map[string]int{},
		cancel: map[string]int{},
	}
}
