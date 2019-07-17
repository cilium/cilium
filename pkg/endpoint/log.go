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
	"sync/atomic"
	"unsafe"

	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"

	"github.com/cilium/cilium/pkg/option"
	"github.com/sirupsen/logrus"
)

var (
	Subsystem = "endpoint"
	log       = logging.DefaultLogger.WithField(logfields.LogSubsys, Subsystem)
)

const (
	fieldRegenLevel = "regeneration-level"
)

// getLogger returns a logrus object with EndpointID, ContainerID and the Endpoint
// revision fields.
func (e *Endpoint) getLogger() *logrus.Entry {
	v := atomic.LoadPointer(&e.logger)
	return (*logrus.Entry)(v)
}

// Logger returns a logrus object with EndpointID, ContainerID and the Endpoint
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
// Note: You must hold Endpoint.Mutex for reading if fields is nil.
func (e *Endpoint) UpdateLogger(fields map[string]interface{}) {
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
	// - If any of EndpointID, ContainerID or policyRevision are different on the
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
		logfields.LogSubsys:              Subsystem,
		logfields.EndpointID:             e.ID,
		logfields.ContainerID:            e.getShortContainerID(),
		logfields.DatapathPolicyRevision: e.policyRevision,
		logfields.DesiredPolicyRevision:  e.nextPolicyRevision,
		logfields.IPv4:                   e.IPv4.String(),
		logfields.IPv6:                   e.IPv6.String(),
		logfields.K8sPodName:             e.GetK8sNamespaceAndPodNameLocked(),
	})

	if e.SecurityIdentity != nil {
		l = l.WithField(logfields.Identity, e.SecurityIdentity.ID.StringID())
	}

	atomic.StorePointer(&e.logger, unsafe.Pointer(l))
}
