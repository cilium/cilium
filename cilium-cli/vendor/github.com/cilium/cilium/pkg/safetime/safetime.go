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

package safetime

import (
	"runtime"
	"time"

	"github.com/cilium/cilium/pkg/logging/logfields"

	log "github.com/sirupsen/logrus"
)

// TimeSinceSafe returns the duration since t. If the duration is negative,
// returns false to indicate the fact.
//
// Used to workaround a malfunctioning monotonic clock.
func TimeSinceSafe(t time.Time, logger *log.Entry) (time.Duration, bool) {
	n := time.Now()
	d := n.Sub(t)

	if d < 0 {
		logger = logger.WithFields(log.Fields{
			logfields.StartTime: t,
			logfields.EndTime:   n,
			logfields.Duration:  d,
		})
		_, file, line, ok := runtime.Caller(1)
		if ok {
			logger = logger.WithFields(log.Fields{
				logfields.Path: file,
				logfields.Line: line,
			})
		}
		logger.Warn("BUG: negative duration")

		return time.Duration(0), false
	}

	return d, true
}
