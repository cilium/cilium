// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package safetime

import (
	"log/slog"
	"runtime"

	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/time"
)

// TimeSinceSafe returns the duration since t. If the duration is negative,
// returns false to indicate the fact.
//
// Used to workaround a malfunctioning monotonic clock.
func TimeSinceSafe(t time.Time, logger *slog.Logger) (time.Duration, bool) {
	n := time.Now()
	d := n.Sub(t)

	if d < 0 {
		scopedLog := logger.With(
			logfields.StartTime, t,
			logfields.EndTime, n,
			logfields.Duration, d,
		)
		_, file, line, ok := runtime.Caller(1)
		if ok {
			scopedLog = scopedLog.With(
				logfields.Path, file,
				logfields.Line, line,
			)
		}
		scopedLog.Warn("BUG: negative duration")

		return time.Duration(0), false
	}

	return d, true
}
