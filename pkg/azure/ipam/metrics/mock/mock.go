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

package mock

import (
	"fmt"
	"time"

	"github.com/cilium/cilium/pkg/lock"
)

type mockMetrics struct {
	mutex          lock.RWMutex
	azureApiCall   map[string]float64
	azureRateLimit map[string]time.Duration
}

// NewMockMetrics returns a new metrics implementation with a mocked backend
func NewMockMetrics() *mockMetrics {
	return &mockMetrics{
		azureApiCall:   map[string]float64{},
		azureRateLimit: map[string]time.Duration{},
	}
}

func (m *mockMetrics) AzureAPICall(operation, status string) float64 {
	m.mutex.RLock()
	defer m.mutex.RUnlock()
	return m.azureApiCall[fmt.Sprintf("operation=%s, status=%s", operation, status)]
}

func (m *mockMetrics) ObserveAzureAPICall(operation, status string, duration float64) {
	m.mutex.Lock()
	m.azureApiCall[fmt.Sprintf("operation=%s, status=%s", operation, status)] += duration
	m.mutex.Unlock()
}

func (m *mockMetrics) AzureRateLimit(operation string) time.Duration {
	m.mutex.RLock()
	defer m.mutex.RUnlock()
	return m.azureRateLimit[operation]
}

func (m *mockMetrics) ObserveAzureRateLimit(operation string, delay time.Duration) {
	m.mutex.Lock()
	m.azureRateLimit[operation] += delay
	m.mutex.Unlock()
}
