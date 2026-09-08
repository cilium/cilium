// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package spire

import (
	"fmt"
	"log/slog"
)

// spiffeLogWrapper is a log wrapper for the SPIRE client logs
// the log levels of this library do not match those from Cilium
// this will be used to convert the log levels.
type spiffeLogWrapper struct {
	log *slog.Logger
}

// newSpiffeLogWrapper returns a new spiffeLogWrapper
func newSpiffeLogWrapper(log *slog.Logger) *spiffeLogWrapper {
	return &spiffeLogWrapper{
		log: log,
	}
}

// Debugf logs a debug message
func (l *spiffeLogWrapper) Debugf(format string, args ...any) {
	l.log.Debug(fmt.Sprintf(format, args...))
}

// Infof logs an info message
func (l *spiffeLogWrapper) Infof(format string, args ...any) {
	l.log.Info(fmt.Sprintf(format, args...))
}

// Warnf logs a warning message
func (l *spiffeLogWrapper) Warnf(format string, args ...any) {
	l.log.Warn(fmt.Sprintf(format, args...))
}

// Errorf logs an error message downgraded to a warning as in our case
// a connection error on startups is expected on initial start of the oprator
// while the SPIRE server is still starting up. Any errors given by spire will
// result in an error passed back to the function caller which then is logged
// as an error.
func (l *spiffeLogWrapper) Errorf(format string, args ...any) {
	l.log.Warn(fmt.Sprintf(format, args...))
}
