// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package endpoint

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"

	"github.com/cilium/lumberjack/v2"

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
		return logging.DefaultSlogLogger.With(logfields.LogSubsys, subsystem)
	}
	logger := e.loggerNoSubsys.Load()
	if logger == nil {
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

	var (
		args   []any
		subsys any
	)
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
	baseLogger := logging.DefaultSlogLogger.With(args...)
	e.loggerNoSubsys.Store(baseLogger)

	// Create a base logger with the subsys attribute.
	args = append(args, logfields.LogSubsys, subsys)
	baseLogger = logging.DefaultSlogLogger.With(args...)

	// If this endpoint is set to debug ensure it will print debug by giving it
	// an independent logger.
	// If this endpoint is not set to debug, it will use the log level set by the user.
	if e.Options != nil && e.Options.IsEnabled(option.Debug) {
		// FIXME @aanm re-enable this functionality once we figure out a solution
		//  to have a logger per subsystem.
		// baseLogger.SetLevel(slog.LevelDebug)
	}

	e.logger.Store(baseLogger)
}

// Only to be called from UpdateLogger() above
func (e *Endpoint) updatePolicyLogger(fields map[string]any) {
	policyLogger := e.policyLogger.Load()
	// e.Options check needed for unit testing.
	if policyLogger == nil && e.Options != nil && e.Options.IsEnabled(option.DebugPolicy) {
		maxSize := 10 // 10 MB
		if ms := os.Getenv("CILIUM_DBG_POLICY_LOG_MAX_SIZE"); ms != "" {
			if ms, err := strconv.Atoi(ms); err == nil {
				maxSize = ms
			}
		}
		maxBackups := 3
		if mb := os.Getenv("CILIUM_DBG_POLICY_LOG_MAX_BACKUPS"); mb != "" {
			if mb, err := strconv.Atoi(mb); err == nil {
				maxBackups = mb
			}
		}
		lumberjackLogger := &lumberjack.Logger{
			Filename:   filepath.Join(option.Config.StateDir, "endpoint-policy.log"),
			MaxSize:    maxSize,
			MaxBackups: maxBackups,
			MaxAge:     28, // days
			LocalTime:  true,
			Compress:   true,
		}
		baseLogger := slog.New(slog.NewTextHandler(lumberjackLogger, &slog.HandlerOptions{
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
