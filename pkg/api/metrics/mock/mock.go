// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

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
