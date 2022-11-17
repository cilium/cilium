// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package endpoint

import (
	"k8s.io/apimachinery/pkg/types"

	"github.com/cilium/cilium/pkg/endpoint/id"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

// GetContainerName returns the name of the container for the endpoint.
func (e *Endpoint) GetContainerName() string {
	e.unconditionalRLock()
	defer e.runlock()
	return e.containerName
}

// SetContainerName modifies the endpoint's container name
func (e *Endpoint) SetContainerName(name string) {
	e.unconditionalLock()
	e.containerName = name
	e.unlock()
}

// GetK8sPodName returns the name of the pod if the endpoint represents a
// Kubernetes pod
func (e *Endpoint) GetK8sPodName() string {
	e.unconditionalRLock()
	k8sPodName := e.K8sPodName
	e.runlock()

	return k8sPodName
}

// HumanStringLocked returns the endpoint's most human readable identifier as string
func (e *Endpoint) HumanStringLocked() string {
	if pod := e.getK8sNamespaceAndPodName(); pod != "" {
		return pod
	}

	return e.StringID()
}

// GetK8sNamespaceAndPodName returns the corresponding namespace and pod
// name for this endpoint.
func (e *Endpoint) GetK8sNamespaceAndPodName() string {
	e.unconditionalRLock()
	defer e.runlock()

	return e.getK8sNamespaceAndPodName()
}

func (e *Endpoint) getK8sNamespaceAndPodName() string {
	return e.K8sNamespace + "/" + e.K8sPodName
}

// SetK8sPodName modifies the endpoint's pod name
func (e *Endpoint) SetK8sPodName(name string) {
	e.unconditionalLock()
	e.K8sPodName = name
	e.UpdateLogger(map[string]interface{}{
		logfields.K8sPodName: e.getK8sNamespaceAndPodName(),
	})
	e.unlock()
}

// SetContainerID modifies the endpoint's container ID
func (e *Endpoint) SetContainerID(id string) {
	e.unconditionalLock()
	e.containerID = id
	e.UpdateLogger(map[string]interface{}{
		logfields.ContainerID: e.getShortContainerID(),
	})
	e.unlock()
}

// GetContainerID returns the endpoint's container ID
func (e *Endpoint) GetContainerID() string {
	e.unconditionalRLock()
	cID := e.containerID
	e.runlock()
	return cID
}

// GetShortContainerID returns the endpoint's shortened container ID
func (e *Endpoint) GetShortContainerID() string {
	e.unconditionalRLock()
	defer e.runlock()

	return e.getShortContainerID()
}

func (e *Endpoint) getShortContainerID() string {
	if e == nil {
		return ""
	}

	caplen := 10
	if len(e.containerID) <= caplen {
		return e.containerID
	}

	return e.containerID[:caplen]

}

// SetDockerEndpointID modifies the endpoint's Docker Endpoint ID
func (e *Endpoint) SetDockerEndpointID(id string) {
	e.unconditionalLock()
	e.dockerEndpointID = id
	e.unlock()
}

func (e *Endpoint) GetDockerEndpointID() string {
	e.unconditionalRLock()
	defer e.runlock()
	return e.dockerEndpointID
}

// SetDockerNetworkID modifies the endpoint's Docker Endpoint ID
func (e *Endpoint) SetDockerNetworkID(id string) {
	e.unconditionalLock()
	e.dockerNetworkID = id
	e.unlock()
}

// GetDockerNetworkID returns the endpoint's Docker Endpoint ID
func (e *Endpoint) GetDockerNetworkID() string {
	e.unconditionalRLock()
	defer e.runlock()

	return e.dockerNetworkID
}

// IdentifiersLocked fetches the set of attributes that uniquely identify the
// endpoint. The caller must hold exclusive control over the endpoint.
func (e *Endpoint) IdentifiersLocked() id.Identifiers {
	refs := make(id.Identifiers, 6)
	if e.containerID != "" {
		refs[id.ContainerIdPrefix] = e.containerID
	}

	if e.dockerEndpointID != "" {
		refs[id.DockerEndpointPrefix] = e.dockerEndpointID
	}

	if e.IPv4.IsValid() {
		refs[id.IPv4Prefix] = e.IPv4.String()
	}

	if e.IPv6.IsValid() {
		refs[id.IPv6Prefix] = e.IPv6.String()
	}

	if e.containerName != "" {
		refs[id.ContainerNamePrefix] = e.containerName
	}

	if podName := e.getK8sNamespaceAndPodName(); podName != "" {
		refs[id.PodNamePrefix] = podName
	}
	return refs
}

// Identifiers fetches the set of attributes that uniquely identify the endpoint.
func (e *Endpoint) Identifiers() (id.Identifiers, error) {
	if err := e.rlockAlive(); err != nil {
		return nil, err
	}
	defer e.runlock()

	return e.IdentifiersLocked(), nil
}

// GetCiliumEndpointUID returns the UID of the CiliumEndpoint.
func (e *Endpoint) GetCiliumEndpointUID() types.UID {
	e.unconditionalRLock()
	defer e.runlock()
	return e.ciliumEndpointUID
}

// SetCiliumEndpointUID modifies the endpoint's CiliumEndpoint UID.
func (e *Endpoint) SetCiliumEndpointUID(uid types.UID) {
	e.unconditionalLock()
	e.ciliumEndpointUID = uid
	e.unlock()
}
