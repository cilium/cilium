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

package workloads

import (
	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/labels"
)

// WorkloadOwner is the interface that the owner of workloads must implement.
type WorkloadOwner interface {
	// DeleteEndpoint is called when the underlying workload has died
	DeleteEndpoint(id string) (int, error)

	// EndpointLabelsUpdate is called whenever the labels of an endpoint
	// should be updated. This function must update the identity of the
	// endpoint and trigger policy & program regeneration as required.
	EndpointLabelsUpdate(ep *endpoint.Endpoint, identityLabels, infoLabels labels.Labels) error
}

var (
	owner WorkloadOwner
)

// Owner returns the owner instance of all workloads
func Owner() WorkloadOwner {
	return owner
}

// Init initializes the workloads package
func Init(o WorkloadOwner) {
	owner = o
}
