// Copyright 2017-2018 Authors of Cilium
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

	"github.com/sirupsen/logrus"
)

var log = logging.DefaultLogger.WithField(logfields.LogSubsys, "endpoint")

// logger returns a logrus object with EndpointID, ContainerID and the Endpoint
// revision fields.
// Note: You must hold Endpoint.Mutex for reading
func (e *Endpoint) getLogger() *logrus.Entry {
	e.updateLogger()

	v := atomic.LoadPointer(&e.logger)

	return (*logrus.Entry)(v)
}

// updateLogger creates a logger instance specific to this endpoint. It will
// create a custom Debug logger for this endpoint when the option on it is set.
// Note: You must hold Endpoint.Mutex for reading
func (e *Endpoint) updateLogger() {
	containerID := e.getShortContainerID()

	podName := e.GetK8sNamespaceAndPodNameLocked()

	// We need to update if
	// - e.logger is nil (this happens on the first ever call to updateLogger via
	//   getLogger above). This clause has to come first to guard the others.
	// - If any of EndpointID, ContainerID or policyRevision are different on the
	//   endpoint from the logger.
	// - The debug option on the endpoint is true, and the logger is not debug,
	//   or vice versa.
	v := atomic.LoadPointer(&e.logger)
	epLogger := (*logrus.Entry)(v)
	shouldUpdate := epLogger == nil || e.Options == nil ||
		epLogger.Data[logfields.EndpointID] != e.ID ||
		epLogger.Data[logfields.ContainerID] != containerID ||
		epLogger.Data[logfields.PolicyRevision] != e.policyRevision ||
		epLogger.Data[logfields.IPv4] != e.IPv4.String() ||
		epLogger.Data[logfields.IPv6] != e.IPv6.String() ||
		epLogger.Data[logfields.K8sPodName] != podName ||
		e.Options.IsEnabled("Debug") != (epLogger.Level == logrus.DebugLevel)

	// do nothing if we do not need an update
	if !shouldUpdate {
		return
	}

	// default to using the log var set above
	baseLogger := log.Logger

	// If this endpoint is set to debug ensure it will print debug by giving it
	// an independent logger
	if e.Options != nil && e.Options.IsEnabled("Debug") {
		baseLogger = logging.InitializeDefaultLogger()
		baseLogger.SetLevel(logrus.DebugLevel)
	}

	l := baseLogger.WithFields(logrus.Fields{
		logfields.EndpointID:     e.ID,
		logfields.ContainerID:    containerID,
		logfields.PolicyRevision: e.policyRevision,
		logfields.IPv4:           e.IPv4.String(),
		logfields.IPv6:           e.IPv6.String(),
		logfields.K8sPodName:     podName,
	})

	atomic.StorePointer(&e.logger, unsafe.Pointer(l))
}
