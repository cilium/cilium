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
	"github.com/cilium/cilium/pkg/logfields"

	log "github.com/sirupsen/logrus"
)

// logger returns a logrus object with EndpointID, ContainerID and the Endpoint
// revision fields.
// Note: You must host Endpoint.Mutex
func (e *Endpoint) getLogger() *log.Entry {
	if e.logger == nil {
		e.updateLogger()
	}
	return e.logger
}

// updateLogger
// Note: You must hold Endpoint.Mutex
func (e *Endpoint) updateLogger() {
	e.logger = log.WithFields(log.Fields{
		logfields.EndpointID:  e.ID,
		logfields.ContainerID: e.DockerID,
		"policyRevision":      e.policyRevision,
	})
}
