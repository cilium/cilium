// Copyright 2017 Authors of Cilium
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
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"

	"github.com/sirupsen/logrus"
)

var log = logging.DefaultLogger

// logger returns a logrus object with EndpointID, ContainerID and the Endpoint
// revision fields.
// Note: You must hold Endpoint.Mutex
func (e *Endpoint) getLogger() *logrus.Entry {
	e.updateLogger()
	return e.logger
}

// updateLogger creates a logger instance specific to this endpoint. It will
// create a custom Debug logger for this endpoint when the option on it is set.
// Note: You must hold Endpoint.Mutex
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
	shouldUpdate := e.logger == nil ||
		e.logger.Data[logfields.EndpointID] != e.ID ||
		e.logger.Data[logfields.ContainerID] != containerID ||
		e.logger.Data[logfields.PolicyRevision] != e.policyRevision ||
		e.logger.Data[logfields.IPv4] != e.IPv4.String() ||
		e.logger.Data[logfields.IPv6] != e.IPv6.String() ||
		e.logger.Data[logfields.K8sPodName] != podName ||
		e.Options.IsEnabled("Debug") != (e.logger.Level == logrus.DebugLevel)

	// do nothing if we do not need an update
	if !shouldUpdate {
		return
	}

	// default to using the log var set above
	baseLogger := log

	// If this endpoint is set to debug ensure it will print debug by giving it
	// an independent logger
	if e.Options != nil && e.Options.IsEnabled("Debug") {
		baseLogger = logging.InitializeDefaultLogger()
		baseLogger.SetLevel(logrus.DebugLevel)
	}

	// update the logger object.
	// Note: endpoint.Mutex protects the reference but not the logger objects. We
	// cannot update the old object directly as that could be racey.
	e.logger = baseLogger.WithFields(logrus.Fields{
		logfields.EndpointID:     e.ID,
		logfields.ContainerID:    containerID,
		logfields.PolicyRevision: e.policyRevision,
		logfields.IPv4:           e.IPv4.String(),
		logfields.IPv6:           e.IPv6.String(),
		logfields.K8sPodName:     podName,
	})
}
