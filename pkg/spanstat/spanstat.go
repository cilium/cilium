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
// and Stop() calls
type SpanStat struct {
	spanStart     time.Time
	totalDuration time.Duration
}

// Start starts a new span
func (s *SpanStat) Start() {
	s.spanStart = time.Now()
}

// End ends the current span and adds the measured duration to the total
func (s *SpanStat) End() {
	s.totalDuration += time.Since(s.spanStart)
}

// Total returns the total duration of all spans measured
func (s *SpanStat) Total() time.Duration {
	return s.totalDuration
}

// Reset rests the duration measurement
func (s *SpanStat) Reset() {
	s.totalDuration = 0
}
