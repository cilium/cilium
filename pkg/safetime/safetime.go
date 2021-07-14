// SPDX-License-Identifier: Apache-2.0
// Copyright 2018 Authors of Cilium

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
