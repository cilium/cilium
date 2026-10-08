// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package kvstore

import (
	"log/slog"
)

var (
	traceEnabled bool
)

// EnableTracing enables kvstore tracing
func EnableTracing() {
	traceEnabled = true
}

// Trace is used to trace kvstore debug messages
func Trace(logger *slog.Logger, msg string, fields ...any) {
	if traceEnabled {
		logger.Debug(
			msg,
			fields...,
		)
	}
}
