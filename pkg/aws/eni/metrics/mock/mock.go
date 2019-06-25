// Copyright 2019 Authors of Cilium
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

package mock

type mockMetrics struct{}

// NewMockMetrics returns a new metrics implementation with a mocked backend
func NewMockMetrics() *mockMetrics {
	return &mockMetrics{}
}

func (m *mockMetrics) IncENIAllocationAttempt(status, subnetID string)              {}
func (m *mockMetrics) AddIPAllocation(subnetID string, allocated int64)             {}
func (m *mockMetrics) SetAllocatedIPs(typ string, allocated int)                    {}
func (m *mockMetrics) SetAvailableENIs(available int)                               {}
func (m *mockMetrics) SetNodesAtCapacity(nodes int)                                 {}
func (m *mockMetrics) ObserveEC2APICall(operation, status string, duration float64) {}
func (m *mockMetrics) IncEC2RateLimit(operation string)                             {}
func (m *mockMetrics) IncResyncCount()                                              {}
