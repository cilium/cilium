// Copyright 2018-2019 Authors of Cilium
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

package spanstat

import (
	"time"

	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/safetime"
)

var (
	subSystem = "spanstat"
	log       = logging.DefaultLogger.WithField(logfields.LogSubsys, subSystem)
)

// SpanStat measures the total duration of all time spent in between Start()
// and Stop() calls.
type SpanStat struct {
	mutex           lock.RWMutex
	spanStart       time.Time
	successDuration time.Duration
	failureDuration time.Duration
}

// Start creates a new SpanStat and starts it
func Start() *SpanStat {
	s := &SpanStat{}
	return s.Start()
}

// Start starts a new span
func (s *SpanStat) Start() *SpanStat {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.spanStart = time.Now()
	return s
}

// EndError calls End() based on the value of err
func (s *SpanStat) EndError(err error) *SpanStat {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	return s.end(err == nil)
}

// End ends the current span and adds the measured duration to the total
// cumulated duration, and to the success or failure cumulated duration
// depending on the given success flag
func (s *SpanStat) End(success bool) *SpanStat {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	return s.end(success)
}

// must be called with Lock() held
func (s *SpanStat) end(success bool) *SpanStat {
	if !s.spanStart.IsZero() {
		d, _ := safetime.TimeSinceSafe(s.spanStart, log)
		if success {
			s.successDuration += d
		} else {
			s.failureDuration += d
		}
	}
	s.spanStart = time.Time{}
	return s
}

// Total returns the total duration of all spans measured, including both
// successes and failures
func (s *SpanStat) Total() time.Duration {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	return s.successDuration + s.failureDuration
}

// SuccessTotal returns the total duration of all successful spans measured
func (s *SpanStat) SuccessTotal() time.Duration {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	return s.successDuration
}

// FailureTotal returns the total duration of all unsuccessful spans measured
func (s *SpanStat) FailureTotal() time.Duration {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	return s.failureDuration
}

// Reset rests the duration measurements
func (s *SpanStat) Reset() {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.successDuration = 0
	s.failureDuration = 0
}

// Seconds returns the number of seconds represents by the spanstat. If a span
// is still open, it is closed first.
func (s *SpanStat) Seconds() float64 {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	if !s.spanStart.IsZero() {
		s.end(true)
	}

	total := s.successDuration + s.failureDuration
	return total.Seconds()
}
