// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package egressgateway

import (
	"net/netip"

	"github.com/cilium/cilium/pkg/labels"
)

// endpointMetadata stores the pod data used by egress gateway policy matching.
type endpointMetadata struct {
	// labels are the endpoint's identity labels.
	labels labels.LabelArray
	// key uniquely identifies the pod (namespace/podName)
	key endpointKey
	// ips are the endpoint's unique IPs
	ips []netip.Addr
	// nodeIP is the IP of the node the endpoint is running on
	nodeIP string
}

// endpointKey uniquely identifies a pod using namespace/podName.
type endpointKey = string
