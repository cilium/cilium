// Copyright 2017-2019 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package endpoint

import (
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"unsafe"

	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"

	"github.com/sirupsen/logrus"
	"gopkg.in/natefinch/lumberjack.v2"
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
	v := atomic.LoadPointer(&e.logger)
	return (*logrus.Entry)(v)
}

// getPolicyLogger returns a logger to be used for policy update debugging, or nil,
// if not configured.
func (e *Endpoint) getPolicyLogger() *logrus.Entry {
	v := atomic.LoadPointer(&e.policyLogger)
	return (*logrus.Entry)(v)
}

// policyDebug logs the 'msg' with 'fields' if policy debug logging is enabled.
func (e *Endpoint) policyDebug(fields logrus.Fields, msg string) {
	if dbgLog := e.getPolicyLogger(); dbgLog != nil {
		dbgLog.WithFields(fields).Debug(msg)
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
// endopoints do not need locks to call this.
func (e *Endpoint) UpdateLogger(fields map[string]interface{}) {
	e.updatePolicyLogger(fields)
	v := atomic.LoadPointer(&e.logger)
	epLogger := (*logrus.Entry)(v)
	if fields != nil && epLogger != nil {
		newLogger := epLogger.WithFields(fields)
		atomic.StorePointer(&e.logger, unsafe.Pointer(newLogger))
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

	// default to using the log var set above
	baseLogger := log.Logger

	// If this endpoint is set to debug ensure it will print debug by giving it
	// an independent logger
	if e.Options != nil && e.Options.IsEnabled(option.Debug) {
		baseLogger = logging.InitializeDefaultLogger()
		baseLogger.SetLevel(logrus.DebugLevel)
	} else {
		// Debug mode takes priority; if not in debug, check what log level user
		// has set and set the endpoint's log to log at that level.
		if lvl, ok := logging.GetLogLevelFromConfig(); ok {
			baseLogger.SetLevel(lvl)
		}
	}

	// When adding new fields, make sure they are abstracted by a setter
	// and update the logger when the value is set.
	l := baseLogger.WithFields(logrus.Fields{
		logfields.LogSubsys:              subsystem,
		logfields.EndpointID:             e.ID,
		logfields.ContainerID:            e.getShortContainerID(),
		logfields.DatapathPolicyRevision: e.policyRevision,
		logfields.DesiredPolicyRevision:  e.nextPolicyRevision,
		logfields.IPv4:                   e.IPv4.String(),
		logfields.IPv6:                   e.IPv6.String(),
		logfields.K8sPodName:             e.getK8sNamespaceAndPodName(),
	})

	if e.SecurityIdentity != nil {
		l = l.WithField(logfields.Identity, e.SecurityIdentity.ID.StringID())
	}

	atomic.StorePointer(&e.logger, unsafe.Pointer(l))
}

// Only to be called from UpdateLogger() above
func (e *Endpoint) updatePolicyLogger(fields map[string]interface{}) {
	pv := atomic.LoadPointer(&e.policyLogger)
	policyLogger := (*logrus.Entry)(pv)
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
		policyLogger = policyLogger.WithFields(logrus.Fields{
			logfields.LogSubsys:              subsystem,
			logfields.EndpointID:             e.ID,
			logfields.ContainerID:            e.getShortContainerID(),
			logfields.DatapathPolicyRevision: e.policyRevision,
			logfields.DesiredPolicyRevision:  e.nextPolicyRevision,
			logfields.IPv4:                   e.IPv4.String(),
			logfields.IPv6:                   e.IPv6.String(),
			logfields.K8sPodName:             e.getK8sNamespaceAndPodName(),
		})

		if e.SecurityIdentity != nil {
			policyLogger = policyLogger.WithField(logfields.Identity, e.SecurityIdentity.ID.StringID())
		}
	}
	atomic.StorePointer(&e.policyLogger, unsafe.Pointer(policyLogger))
}
