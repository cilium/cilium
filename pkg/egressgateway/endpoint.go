// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package egressgateway

import (
	"net/netip"
)

// endpointMetadata stores relevant metadata associated with an endpoint.
// Populated from IPCache notifications rather than directly from CiliumEndpoint
// or CiliumEndpointSlice resources, making it source-agnostic.
type endpointMetadata struct {
	// labels are the endpoint's identity labels (k8s string map form)
	labels map[string]string
	// id uniquely identifies the endpoint (namespace/podName)
	id endpointID
	// ips are the endpoint's unique IPs
	ips []netip.Addr
	// nodeIP is the IP of the node the endpoint is running on
	nodeIP string
}

// endpointID uniquely identifies an endpoint using namespace/podName.
type endpointID = string
