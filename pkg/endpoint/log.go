// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package endpoint

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"

	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/lumberjack/v2"
)

var (
	log       = logging.DefaultLogger.With(slog.String(logfields.LogSubsys, subsystem))
	policyLog = slog.New(log.Handler())
)

const (
	subsystem = "endpoint"

	fieldRegenLevel = "regeneration-level"
)

// getLogger returns a logrus object with EndpointID, containerID and the Endpoint
// revision fields.
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

// Logger returns a logrus object with EndpointID, containerID and the Endpoint
// revision fields. The caller must specify their subsystem.
func (e *Endpoint) Logger(subsystem string) *slog.Logger {
	if e == nil {
		return log.With(slog.String(logfields.LogSubsys, subsystem))
	}

	return e.getLogger().With(slog.String(logfields.LogSubsys, subsystem))
}

// UpdateLogger creates a logger instance specific to this endpoint. It will
// create a custom Debug logger for this endpoint when the option on it is set.
// If fields is not nil only the those specific fields will be updated in the
// endpoint's logger, otherwise a full update of those fields is executed.
//
// Note: You must hold Endpoint.mutex.Lock() to synchronize logger pointer
// updates if the endpoint is already exposed. Callers that create new
// endpoints do not need locks to call this.
func (e *Endpoint) UpdateLogger(fields map[string]interface{}) {
	e.updatePolicyLogger(fields)
	epLogger := e.logger.Load()
	if fields != nil && epLogger != nil {
		var attrs []any
		for k, v := range fields {
			attrs = append(attrs, slog.Any(k, v))
		}
		newLogger := epLogger.With(attrs...)
		e.logger.Store(newLogger)
		return
	}

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
	f := []any{
		slog.String(logfields.LogSubsys, subsystem),
		slog.Uint64(logfields.EndpointID, uint64(e.ID)),
		slog.String(logfields.ContainerID, e.GetShortContainerID()),
		slog.String(logfields.ContainerInterface, e.containerIfName),
		slog.Uint64(logfields.DatapathPolicyRevision, e.policyRevision),
		slog.Uint64(logfields.DesiredPolicyRevision, e.nextPolicyRevision),
		slog.String(logfields.IPv4, e.GetIPv4Address()),
		slog.String(logfields.IPv6, e.GetIPv6Address()),
		slog.String(logfields.K8sPodName, e.GetK8sNamespaceAndPodName()),
		slog.String(logfields.CEPName, e.GetK8sNamespaceAndCEPName()),
	}

	if e.SecurityIdentity != nil {
		f = append(f, slog.String(logfields.Identity, e.SecurityIdentity.ID.StringID()))
	}

	// Inherit properties from default logger.
	baseLogger := logging.DefaultLogger.With(f...)

	// If this endpoint is set to debug ensure it will print debug by giving it
	// an independent logger.
	// If this endpoint is not set to debug, it will use the log level set by the user.
	if e.Options != nil && e.Options.IsEnabled(option.Debug) {
		// FIXME @aanm
		// baseLogger.Logger.SetLevel(logrus.DebugLevel)
	}

	e.logger.Store(baseLogger)
}

// Only to be called from UpdateLogger() above
func (e *Endpoint) updatePolicyLogger(fields map[string]interface{}) {
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
		// FIXME @aanm
		_ = lumberjackLogger
		// policyLog.SetOutput(lumberjackLogger)
		// policyLog.SetLevel(logrus.DebugLevel)
		// policyLog.SetFormatter(logging.GetHandler(logging.DefaultLogFormatTimestamp))

		policyLogger = policyLog
	}
	if policyLogger == nil || e.Options == nil {
		return
	}

	if !e.Options.IsEnabled(option.DebugPolicy) {
		policyLogger = nil
	} else if fields != nil {
		var attrs []any
		for k, v := range fields {
			attrs = append(attrs, slog.Any(k, v))
		}
		policyLogger = policyLogger.With(attrs...)
	} else {
		f := []any{
			slog.String(logfields.LogSubsys, subsystem),
			slog.Uint64(logfields.EndpointID, uint64(e.ID)),
			slog.String(logfields.ContainerID, e.GetShortContainerID()),
			slog.Uint64(logfields.DatapathPolicyRevision, e.policyRevision),
			slog.Uint64(logfields.DesiredPolicyRevision, e.nextPolicyRevision),
			slog.String(logfields.IPv4, e.GetIPv4Address()),
			slog.String(logfields.IPv6, e.GetIPv6Address()),
			slog.String(logfields.K8sPodName, e.GetK8sNamespaceAndPodName()),
		}

		if e.SecurityIdentity != nil {
			f = append(f, slog.String(logfields.Identity, e.SecurityIdentity.ID.StringID()))
		}

		policyLogger = policyLogger.With(f...)
	}
	e.policyLogger.Store(policyLogger)
}
