// Copyright 2018 Authors of Cilium
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
)

// SpanStat measures the total duration of all time spent in between Start()
// and Stop() calls.
type SpanStat struct {
	spanStart       time.Time
	successDuration time.Duration
	failureDuration time.Duration
}

// Start starts a new span
func (s *SpanStat) Start() {
	s.spanStart = time.Now()
}

// End ends the current span and adds the measured duration to the total
// cumulated duration, and to the success or failure cumulated duration
// depending on the given success flag
func (s *SpanStat) End(success bool) {
	if !s.spanStart.IsZero() {
		d := time.Since(s.spanStart)
		if success {
			s.successDuration += d
		} else {
			s.failureDuration += d
		}
	}
	s.spanStart = time.Time{}
}

// Total returns the total duration of all spans measured, including both
// successes and failures
func (s *SpanStat) Total() time.Duration {
	return s.successDuration + s.failureDuration
}

// SuccessTotal returns the total duration of all successful spans measured
func (s *SpanStat) SuccessTotal() time.Duration {
	return s.successDuration
}

// FailureTotal returns the total duration of all successful spans measured
func (s *SpanStat) FailureTotal() time.Duration {
	return s.failureDuration
}

// Reset rests the duration measurements
func (s *SpanStat) Reset() {
	s.successDuration = 0
	s.failureDuration = 0
}
