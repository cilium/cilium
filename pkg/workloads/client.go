// Copyright 2016-2018 Authors of Cilium
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
	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/endpoint"
)

var (
	// defaultClient is the default client initialized by initClient
	defaultClient WorkloadRuntime
)

func initClient(module workloadModule) error {
	c, err := module.newClient()
	if err != nil {
		return err
	}

	defaultClient = c

	return nil
}

// Client returns the global WorkloadRuntime being used.
func Client() WorkloadRuntime {
	return defaultClient
}

// IsRunning returns false if the provided endpoint cannot be associated with a
// running workload. The runtime must be reachable to make this decision.
func IsRunning(ep *endpoint.Endpoint) bool {
	if Client() == nil {
		return false
	}

	return Client().IsRunning(ep)
}

// Status returns the status of the workload runtime
func Status() *models.Status {
	return Client().Status()
}

// EnableEventListener watches for docker events. Performs the plumbing for the
// containers started or dead.
func EnableEventListener() error {
	return Client().EnableEventListener()
}

// IgnoreRunningWorkloads checks for already running containers and checks
// their IP address, then adds the containers to the list of ignored containers
// and allocates the IPs they are using to prevent future collisions.
func IgnoreRunningWorkloads() {
	Client().IgnoreRunningWorkloads()
}
