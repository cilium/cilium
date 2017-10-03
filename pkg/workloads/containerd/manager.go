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

package containerd

import (
	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/endpoint"

	"github.com/docker/engine-api/client"
	ctx "golang.org/x/net/context"
)

// IsRunning returns false if the provided endpoint cannot be associated with a
// running workload. The runtime must be reachable to make this decision.
func IsRunning(ep *endpoint.Endpoint) bool {
	runtimeRunning := false

	networkID := ep.GetDockerNetworkID()
	containerID := ep.GetContainerID()

	if networkID != "" {
		nls, err := dockerClient.NetworkInspect(ctx.Background(), networkID)
		if client.IsErrNetworkNotFound(err) {
			return false
		}

		if err == nil {
			runtimeRunning = true
			found := false
			for _, v := range nls.Containers {
				if v.EndpointID == ep.DockerEndpointID {
					found = true
					break
				}
			}

			if found {
				return found
			}
		}
	}

	if containerID != "" {
		cont, err := dockerClient.ContainerInspect(ctx.Background(), containerID)
		if client.IsErrContainerNotFound(err) {
			return false
		}

		if err == nil {
			runtimeRunning = true

			// Container may exist but is not in running state
			return cont.State.Running
		}
	}

	return !runtimeRunning
}

// Status returns the status of the workload runtime
func Status() *models.Status {
	if _, err := dockerClient.Info(ctx.Background()); err != nil {
		return &models.Status{State: models.StatusStateFailure, Msg: err.Error()}
	}

	return &models.Status{State: models.StatusStateOk, Msg: ""}
}
