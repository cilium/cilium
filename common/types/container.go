//
// Copyright 2016 Authors of Cilium
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
//
package types

import (
	dTypes "github.com/docker/engine-api/types"
	k8sDockerLbls "k8s.io/client-go/1.5/pkg/kubelet/types"
)

type Container struct {
	dTypes.ContainerJSON
	OpLabels OpLabels
	NRetries uint
}

func (c *Container) IsDockerOrInfracontainer() bool {
	if c.Config != nil {
		contName, exists := c.Config.Labels[k8sDockerLbls.KubernetesContainerNameLabel]
		return !exists || contName == "POD"
	}
	return false
}
