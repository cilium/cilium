// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package dnsproxy

import (
	"context"
	"log/slog"

	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

// dnsRequestLogger defers the relatively expensive slog.Logger.With calls
// until this request emits a log record. Scope extensions are kept separate so
// handlers observe the same attribute ordering and WithAttrs call boundaries
// as an eagerly scoped logger.
type dnsRequestLogger struct {
	base   *slog.Logger
	scoped *slog.Logger

	ipPort    string
	requestID uint16

	name    string
	hasName bool

	endpointID       string
	endpointIdentity identity.NumericIdentity
	hasEndpoint      bool
}

func newDNSRequestLogger(base *slog.Logger, ipPort string, requestID uint16, skipDisabledDebugLogScope bool) *dnsRequestLogger {
	logger := &dnsRequestLogger{
		base:      base,
		ipPort:    ipPort,
		requestID: requestID,
	}
	if !skipDisabledDebugLogScope {
		logger.logger()
	}
	return logger
}

func (l *dnsRequestLogger) withName(name string) {
	l.name = name
	l.hasName = true
	if l.scoped != nil {
		l.scoped = l.scoped.With(logfields.DNSName, name)
	}
}

func (l *dnsRequestLogger) withEndpoint(endpointID string, endpointIdentity identity.NumericIdentity) {
	l.endpointID = endpointID
	l.endpointIdentity = endpointIdentity
	l.hasEndpoint = true
	if l.scoped != nil {
		l.scoped = l.scoped.With(
			logfields.EndpointID, endpointID,
			logfields.Identity, endpointIdentity,
		)
	}
}

func (l *dnsRequestLogger) logger() *slog.Logger {
	if l.scoped != nil {
		return l.scoped
	}

	l.scoped = l.base.With(
		logfields.IPAddr, l.ipPort,
		logfields.DNSRequestID, l.requestID,
	)
	if l.hasName {
		l.scoped = l.scoped.With(logfields.DNSName, l.name)
	}
	if l.hasEndpoint {
		l.scoped = l.scoped.With(
			logfields.EndpointID, l.endpointID,
			logfields.Identity, l.endpointIdentity,
		)
	}
	return l.scoped
}

// debugLogger returns nil when debug logging is disabled, avoiding both the
// scoped logger construction and an unscoped fallback log if levels change.
func (l *dnsRequestLogger) debugLogger() *slog.Logger {
	if l.scoped == nil && !l.base.Enabled(context.Background(), slog.LevelDebug) {
		return nil
	}
	return l.logger()
}
