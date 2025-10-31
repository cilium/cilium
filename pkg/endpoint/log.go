// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package endpoint

import (
	"context"
	"log/slog"

	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"
)

const (
	subsystem = "endpoint"

	fieldRegenLevel = "regeneration-level"
)

// getLogger returns a slog.Logger with the fields that represent this endpoint.
func (e *Endpoint) getLogger() *slog.Logger {
	return e.logger.Load()
}

// getPolicyLogger returns a logger to be used for policy update debugging, or nil,
// if not configured.
func (e *Endpoint) getPolicyLogger() *slog.Logger {
	return e.policyLogger.Load()
}

// PolicyDebug logs the 'msg' with 'fields' if policy debug logging is enabled.
func (e *Endpoint) PolicyDebug(msg string, attrs ...any) {
	if dbgLog := e.getPolicyLogger(); dbgLog != nil {
		dbgLog.Debug(msg, attrs...)
	}
}

// Logger returns a slog.Logger object with EndpointID, containerID and the Endpoint
// revision fields. The caller must specify their subsystem. If the endpoint is
// nil or its internal loger is not setup, it returns the default logger.
func (e *Endpoint) Logger(subsystem string) *slog.Logger {
	if e == nil {
		// slogloggercheck: it's safe to use the default logger here as it has been initialized by the program up to this point.
		return logging.DefaultSlogLogger.With(logfields.LogSubsys, subsystem)
	}
	logger := e.loggerNoSubsys.Load()
	if logger == nil {
		// slogloggercheck: it's safe to use the default logger here as it has been initialized by the program up to this point.
		return logging.DefaultSlogLogger.With(logfields.LogSubsys, subsystem)
	}

	return logger.With(logfields.LogSubsys, subsystem)
}

// UpdateLogger creates a logger instance specific to this endpoint. It will
// create a custom Debug logger for this endpoint when the option on it is set.
// If fields is not nil only the those specific fields will be updated in the
// endpoint's logger, otherwise a full update of those fields is executed.
//
// Note: You must hold Endpoint.mutex.Lock() to synchronize logger pointer
// updates if the endpoint is already exposed. Callers that create new
// endpoints do not need locks to call this.
func (e *Endpoint) UpdateLogger(fields map[string]any) {
	e.updatePolicyLogger(fields)
	epLogger := e.logger.Load()
	if fields != nil && epLogger != nil {
		for k, v := range fields {
			e.loggerAttrs.Store(k, v)
		}
	} else {
		// We need to update if
		// - e.logger is nil (this happens on the first ever call to UpdateLogger via
		//   Logger above). This clause has to come first to guard the others.
		// - If any of EndpointID, containerID or policyRevision are different on the
		//   endpoint from the logger.
		// - The debug option on the endpoint is true, and the logger is not debug,
		//   or vice versa.
		shouldUpdate := epLogger == nil || (e.Options != nil &&
			e.Options.IsEnabled(option.Debug) != (epLogger.Enabled(context.Background(), slog.LevelDebug)))

		// do nothing if we do not need an update
		if !shouldUpdate {
			return
		}

		// When adding new fields, make sure they are abstracted by a setter
		// and update the logger when the value is set.
		e.loggerAttrs.Store(logfields.LogSubsys, subsystem)
		e.loggerAttrs.Store(logfields.EndpointID, e.ID)
		e.loggerAttrs.Store(logfields.ContainerID, e.GetShortContainerID())
		e.loggerAttrs.Store(logfields.ContainerInterface, e.containerIfName)
		e.loggerAttrs.Store(logfields.DatapathPolicyRevision, e.policyRevision)
		e.loggerAttrs.Store(logfields.DesiredPolicyRevision, e.nextPolicyRevision)
		e.loggerAttrs.Store(logfields.IPv4, e.GetIPv4Address())
		e.loggerAttrs.Store(logfields.IPv6, e.GetIPv6Address())
		e.loggerAttrs.Store(logfields.K8sPodName, e.GetK8sNamespaceAndPodName())
		e.loggerAttrs.Store(logfields.CEPName, e.GetK8sNamespaceAndCEPName())

		if e.SecurityIdentity != nil {
			e.loggerAttrs.Store(logfields.Identity, e.SecurityIdentity.ID.StringID())
		}
	}

	// Pre-count the attributes to allocate the exact capacity needed
	var (
		subsys any
		// Pre-allocate slice with exact capacity (key+value pair for each attribute)
		// 11 is the number of attributes we store in e.loggerAttrs, minus the logfields.LogSubsys attribute)
		args = make([]any, 0, 2*(11-1))
	)

	// Fill the pre-allocated slice
	e.loggerAttrs.Range(func(k string, v any) bool {
		// Skip the subsys field so that we can use 'args' for both loggers
		if k == logfields.LogSubsys {
			subsys = v
			return true
		}
		args = append(args, k, v)
		return true
	})

	// Create a base logger without the subsys attribute for the endpoint so
	// that we can use it in the func Logger(subsystem string) *slog.Logger
	// slogloggercheck: it's safe to use the default logger here as it has been initialized by the program up to this point.
	baseLogger := logging.DefaultSlogLogger.With(args...)
	e.loggerNoSubsys.Store(baseLogger)

	// Create a base logger with the subsys attribute.
	baseLoggerWithSubsys := baseLogger.With(logfields.LogSubsys, subsys)

	e.logger.Store(baseLoggerWithSubsys)
}

// Only to be called from UpdateLogger() above
func (e *Endpoint) updatePolicyLogger(fields map[string]any) {
	policyLogger := e.policyLogger.Load()
	// e.Options check needed for unit testing.
	if policyLogger == nil && e.Options != nil && e.Options.IsEnabled(option.DebugPolicy) {
		baseLogger := slog.New(slog.NewTextHandler(e.policyDebugLog, &slog.HandlerOptions{
			Level:       slog.LevelDebug,
			ReplaceAttr: logging.ReplaceAttrFn,
		}))
		e.basePolicyLogger.Store(baseLogger)

		policyLogger = baseLogger
	}
	if policyLogger == nil || e.Options == nil {
		return
	}

	if !e.Options.IsEnabled(option.DebugPolicy) {
		policyLogger = nil
		e.basePolicyLogger.Store(nil)
	} else {
		if fields != nil {
			for k, v := range fields {
				e.policyLoggerAttrs.Store(k, v)
			}
		} else {
			e.policyLoggerAttrs.Store(logfields.LogSubsys, subsystem)
			e.policyLoggerAttrs.Store(logfields.EndpointID, e.ID)
			e.policyLoggerAttrs.Store(logfields.ContainerID, e.GetShortContainerID())
			e.policyLoggerAttrs.Store(logfields.DatapathPolicyRevision, e.policyRevision)
			e.policyLoggerAttrs.Store(logfields.DesiredPolicyRevision, e.nextPolicyRevision)
			e.policyLoggerAttrs.Store(logfields.IPv4, e.GetIPv4Address())
			e.policyLoggerAttrs.Store(logfields.IPv6, e.GetIPv6Address())
			e.policyLoggerAttrs.Store(logfields.K8sPodName, e.GetK8sNamespaceAndPodName())

			if e.SecurityIdentity != nil {
				e.policyLoggerAttrs.Store(logfields.Identity, e.SecurityIdentity.ID.StringID())
			}

		}
		var attrs []any
		e.policyLoggerAttrs.Range(func(k string, v any) bool {
			attrs = append(attrs, k, v)
			return true
		})

		policyLogger = e.basePolicyLogger.Load().With(attrs...)
	}
	e.policyLogger.Store(policyLogger)
}
