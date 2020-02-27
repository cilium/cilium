// Copyright 2019-2020 Authors of Cilium
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

// MockMetrics is a mock implementation of pkg/api/metrics
type MockMetrics struct {
	mutex     lock.RWMutex
	apiCall   map[string]float64
	rateLimit map[string]time.Duration
}

// NewMockMetrics returns a new metrics implementation with a mocked backend
func NewMockMetrics() *MockMetrics {
	return &MockMetrics{
		apiCall:   map[string]float64{},
		rateLimit: map[string]time.Duration{},
	}
}

// APICall returns the sum of all durations of all API for a given operation
// and status
func (m *MockMetrics) APICall(operation, status string) float64 {
	m.mutex.RLock()
	defer m.mutex.RUnlock()
	return m.apiCall[fmt.Sprintf("operation=%s, status=%s", operation, status)]
}

// ObserveAPICall must be called on every API call made with the operation
// performed, the status code received and the duration of the call. The
// duration of the API call will be observed. The total can be retrieved with
// APICall().
func (m *MockMetrics) ObserveAPICall(operation, status string, duration float64) {
	m.mutex.Lock()
	m.apiCall[fmt.Sprintf("operation=%s, status=%s", operation, status)] += duration
	m.mutex.Unlock()
}

// RateLimit returns the sum of all rate limited durations of all API for a
// given operation
func (m *MockMetrics) RateLimit(operation string) time.Duration {
	m.mutex.RLock()
	defer m.mutex.RUnlock()
	return m.rateLimit[operation]
}

// ObserveRateLimit must be called in case an API call was subject to rate
// limiting. The duration of the rate-limiting will be observed. The taotal of
// all durations can be retrieve with RateLimit().
func (m *MockMetrics) ObserveRateLimit(operation string, delay time.Duration) {
	m.mutex.Lock()
	m.rateLimit[operation] += delay
	m.mutex.Unlock()
}
