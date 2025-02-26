// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package flowdebug

import (
	"log/slog"
)

var perFlowDebug = false

// Enable enables per-flow debugging
func Enable() {
	perFlowDebug = true
}

// Enabled reports the status of per-flow debugging
func Enabled() bool {
	return perFlowDebug
}

// Log must be used to log any debug messages emitted per request/message/connection
func Log(f func() (l *slog.Logger, msg string)) {
	if perFlowDebug {
		l, args := f()
		l.Debug(args)
	}
}
