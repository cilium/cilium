// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package flowdebug

import (
	"github.com/sirupsen/logrus"
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
func Log(l *logrus.Entry, args ...interface{}) {
	if perFlowDebug {
		l.Debug(args...)
	}
}

// Logf must be used to log any debug messages emitted per request/message/connection
func Logf(l *logrus.Entry, format string, args ...interface{}) {
	if perFlowDebug {
		l.Debugf(format, args...)
	}
}
