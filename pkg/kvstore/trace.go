// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package kvstore

import (
	"log/slog"

	"github.com/cilium/cilium/pkg/logging/logfields"
)

var (
	traceEnabled bool
)

// EnableTracing enables kvstore tracing
func EnableTracing() {
	traceEnabled = true
}

// Trace is used to trace kvstore debug messages
func Trace(msg string, err error, fields ...slog.Attr) {
	if traceEnabled {
		log.Debug(
			msg,
			slog.Any(logfields.Error, err),
			fields,
		)
	}
}
