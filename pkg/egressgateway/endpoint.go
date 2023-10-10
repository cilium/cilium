// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package egressgateway

import (
	"fmt"
	"net/netip"

	"k8s.io/apimachinery/pkg/types"

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
}

// endpointID includes endpoint name and namespace
type endpointID = types.NamespacedName

func getEndpointMetadata(endpoint *k8sTypes.CiliumEndpoint, identityLabels labels.Labels) (*endpointMetadata, error) {
	var addrs []netip.Addr
	id := types.NamespacedName{
		Name:      endpoint.GetName(),
		Namespace: endpoint.GetNamespace(),
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
	}

	if endpoint.Identity == nil {
		return nil, fmt.Errorf("endpoint has no identity metadata")
	}

	data := &endpointMetadata{
		ips:    addrs,
		labels: identityLabels.K8sStringMap(),
		id:     id,
	}

	return data, nil
}
