package types

import (
	dTypes "github.com/docker/engine-api/types"
	k8sDockerLbls "k8s.io/kubernetes/pkg/kubelet/types"
)

type Container struct {
	dTypes.ContainerJSON
	OpLabels OpLabels
}

func (c *Container) IsDockerAndInfracontainer() bool {
	if c.Config != nil {
		contName, exists := c.Config.Labels[k8sDockerLbls.KubernetesContainerNameLabel]
		return !exists || contName == "POD"
	}
	return false
}
