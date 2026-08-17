// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package reconciler

type mockMetrics struct {
	allocated map[TypeLabel]uint64
	total map[TypeLabel]uint64
	pressure map[TypeLabel]float64
}

func newMockMetrics() *mockMetrics {
	return &mockMetrics{}
}

func (m *mockMetrics) SetKeysAllocated(typeLabel TypeLabel, allocated uint64) {
	m.allocated[typeLabel] = allocated
}

func (m *mockMetrics) SetKeysTotal(typeLabel TypeLabel, total uint64) {
	m.total[typeLabel] = total
}

func (m *mockMetrics) SetKeyspacePressure(typeLabel TypeLabel, pressure float64) {
	m.pressure[typeLabel] = pressure
}

