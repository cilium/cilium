// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package kvstore

import (
	"github.com/sirupsen/logrus"
)

var (
	traceEnabled bool
)

// EnableTracing enables kvstore tracing
func EnableTracing() {
	traceEnabled = true
}

// Trace is used to trace kvstore debug messages
func Trace(format string, err error, fields logrus.Fields, a ...interface{}) {
	if traceEnabled {
		log.WithError(err).WithFields(fields).Debugf(format)
	}
}
