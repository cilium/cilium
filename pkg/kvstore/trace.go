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
func Trace(msg string, err error, fields logrus.Fields) {
	if traceEnabled {
		log.WithError(err).WithFields(fields).Debug(msg)
	}
}
