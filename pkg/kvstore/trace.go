// SPDX-License-Identifier: Apache-2.0
// Copyright 2016-2018 Authors of Cilium

package kvstore

import (
	"strings"

	"github.com/cilium/cilium/pkg/logging"

	"github.com/sirupsen/logrus"
)

var (
	// Debugging can be enabled at compile with:
	// -ldflags "-X "github.com/cilium/cilium/pkg/kvstore".Debug=true"
	Debug string

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

func init() {
	if strings.ToLower(Debug) == "true" {
		logging.DefaultLogger.SetLevel(logrus.DebugLevel)
		traceEnabled = true
	}
}
