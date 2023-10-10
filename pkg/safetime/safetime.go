// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package safetime

import (
	"runtime"

	"github.com/sirupsen/logrus"

	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/time"
)

// TimeSinceSafe returns the duration since t. If the duration is negative,
// returns false to indicate the fact.
//
// Used to workaround a malfunctioning monotonic clock.
func TimeSinceSafe(t time.Time, logger *logrus.Entry) (time.Duration, bool) {
	n := time.Now()
	d := n.Sub(t)

	if d < 0 {
		logger = logger.WithFields(logrus.Fields{
			logfields.StartTime: t,
			logfields.EndTime:   n,
			logfields.Duration:  d,
		})
		_, file, line, ok := runtime.Caller(1)
		if ok {
			logger = logger.WithFields(logrus.Fields{
				logfields.Path: file,
				logfields.Line: line,
			})
		}
		logger.Warn("BUG: negative duration")

		return time.Duration(0), false
	}

	return d, true
}
