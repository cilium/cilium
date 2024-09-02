// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package endpoint

import (
	"os"
	"path/filepath"
	"strconv"
	"sync"

	"github.com/cilium/lumberjack/v2"
	"github.com/sirupsen/logrus"

	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"
)

var (
	log       = logging.DefaultLogger.WithField(logfields.LogSubsys, subsystem)
	policyLog = logrus.New()

	policyLogOnce sync.Once
)

const (
	subsystem = "endpoint"

	fieldRegenLevel = "regeneration-level"
)

// getLogger returns a logrus object with EndpointID, containerID and the Endpoint
// revision fields.
func (e *Endpoint) getLogger() *logrus.Entry {
	return e.logger.Load()
}

// getPolicyLogger returns a logger to be used for policy update debugging, or nil,
// if not configured.
func (e *Endpoint) getPolicyLogger() *logrus.Entry {
	return e.policyLogger.Load()
}

// PolicyDebug logs the 'msg' with 'fields' if policy debug logging is enabled.
func (e *Endpoint) PolicyDebug(fields logrus.Fields, msg string) {
	if dbgLog := e.getPolicyLogger(); dbgLog != nil {
		if fields == nil {
			dbgLog.Debug(msg)
		} else {
			dbgLog.WithFields(fields).Debug(msg)
		}
	}
}

// Logger returns a logrus object with EndpointID, containerID and the Endpoint
// revision fields. The caller must specify their subsystem.
func (e *Endpoint) Logger(subsystem string) *logrus.Entry {
	if e == nil {
		return log.WithField(logfields.LogSubsys, subsystem)
	}

	return e.getLogger().WithField(logfields.LogSubsys, subsystem)
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
		newLogger := epLogger.WithFields(fields)
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
		e.Options.IsEnabled(option.Debug) != (epLogger.Level == logrus.DebugLevel))

	// do nothing if we do not need an update
	if !shouldUpdate {
		return
	}

	// When adding new fields, make sure they are abstracted by a setter
	// and update the logger when the value is set.
	f := logrus.Fields{
		logfields.LogSubsys:              subsystem,
		logfields.EndpointID:             e.ID,
		logfields.ContainerID:            e.GetShortContainerID(),
		logfields.ContainerInterface:     e.containerIfName,
		logfields.DatapathPolicyRevision: e.policyRevision,
		logfields.DesiredPolicyRevision:  e.nextPolicyRevision,
		logfields.IPv4:                   e.GetIPv4Address(),
		logfields.IPv6:                   e.GetIPv6Address(),
		logfields.K8sPodName:             e.GetK8sNamespaceAndPodName(),
		logfields.CEPName:                e.GetK8sNamespaceAndCEPName(),
	}

	if e.SecurityIdentity != nil {
		f[logfields.Identity] = e.SecurityIdentity.ID.StringID()
	}

	// Inherit properties from default logger.
	baseLogger := logging.DefaultLogger.WithFields(f)

	// If this endpoint is set to debug ensure it will print debug by giving it
	// an independent logger.
	// If this endpoint is not set to debug, it will use the log level set by the user.
	if e.Options != nil && e.Options.IsEnabled(option.Debug) {
		baseLogger.Logger.SetLevel(logrus.DebugLevel)
	}

	e.logger.Store(baseLogger)
}

// Only to be called from UpdateLogger() above
func (e *Endpoint) updatePolicyLogger(fields map[string]interface{}) {
	policyLogger := e.policyLogger.Load()
	// e.Options check needed for unit testing.
	if policyLogger == nil && e.Options != nil && e.Options.IsEnabled(option.DebugPolicy) {
		policyLogOnce.Do(func() {
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
			policyLog.SetOutput(lumberjackLogger)
			policyLog.SetLevel(logrus.DebugLevel)
			policyLog.SetFormatter(logging.GetFormatter(logging.DefaultLogFormatTimestamp))
		})
		policyLogger = logrus.NewEntry(policyLog)
	}
	if policyLogger == nil || e.Options == nil {
		return
	}

	if !e.Options.IsEnabled(option.DebugPolicy) {
		policyLogger = nil
	} else if fields != nil {
		policyLogger = policyLogger.WithFields(fields)
	} else {
		f := logrus.Fields{
			logfields.LogSubsys:              subsystem,
			logfields.EndpointID:             e.ID,
			logfields.ContainerID:            e.GetShortContainerID(),
			logfields.DatapathPolicyRevision: e.policyRevision,
			logfields.DesiredPolicyRevision:  e.nextPolicyRevision,
			logfields.IPv4:                   e.GetIPv4Address(),
			logfields.IPv6:                   e.GetIPv6Address(),
			logfields.K8sPodName:             e.GetK8sNamespaceAndPodName(),
		}

		if e.SecurityIdentity != nil {
			f[logfields.Identity] = e.SecurityIdentity.ID
		}

		policyLogger = policyLogger.WithFields(f)
	}
	e.policyLogger.Store(policyLogger)
}
