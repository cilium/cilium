// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package egressgateway

import (
	"fmt"
	"net/netip"

	k8sTypes "github.com/cilium/cilium/pkg/k8s/types"
	"github.com/cilium/cilium/pkg/labels"
)

// endpointMetadata stores relevant metadata associated with a endpoint that's updated during endpoint
// add/update events
type endpointMetadata struct {
	// Endpoint labels
	labels map[string]string
	// Endpoint ID
	id endpointID
	// ips are endpoint's unique IPs
	ips []netip.Addr
	// nodeIP is the IP of the node the endpoint is on
	nodeIP string
}

// endpointID uniquely identifies an endpoint. For CEP-sourced endpoints this
// is the Kubernetes UID; for CES-sourced endpoints it is namespace/name.
type endpointID = string

func getEndpointMetadata(endpoint *k8sTypes.CiliumEndpoint, identityLabels labels.Labels) (*endpointMetadata, error) {
	var addrs []netip.Addr

	id := endpointID(endpoint.UID)
	if id == "" {
		// CES-sourced endpoints don't carry a Kubernetes UID.
		// Fall back to namespace/name which is unique per endpoint.
		if endpoint.Name == "" {
			return nil, fmt.Errorf("endpoint has neither UID nor Name")
		}
		id = endpointID(endpoint.Namespace + "/" + endpoint.Name)
	}

	if endpoint.Networking == nil {
		return nil, fmt.Errorf("endpoint has no networking metadata")
	}

	if len(endpoint.Networking.Addressing) == 0 {
		return nil, fmt.Errorf("failed to get valid endpoint IPs")
	}

	for _, pair := range endpoint.Networking.Addressing {
		if pair.IPV4 != "" {
			addr, err := netip.ParseAddr(pair.IPV4)
			if err != nil || !addr.Is4() {
				continue
			}
			addrs = append(addrs, addr)
		}
		if pair.IPV6 != "" {
			addr, err := netip.ParseAddr(pair.IPV6)
			if err != nil || !addr.Is6() {
				continue
			}
			addrs = append(addrs, addr)
		}
	}

	data := &endpointMetadata{
		ips:    addrs,
		labels: identityLabels.K8sStringMap(),
		id:     id,
		nodeIP: endpoint.Networking.NodeIP,
	}

	return data, nil
}
