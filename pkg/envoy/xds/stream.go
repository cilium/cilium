// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package xds

import (
	envoy_service_discovery "github.com/cilium/proxy/go/envoy/service/discovery/v3"
)

// Stream is the subset of the gRPC bi-directional stream types which is used
// by Server.
type Stream interface {
	// Send sends a xDS response back to the client.
	Send(*envoy_service_discovery.DiscoveryResponse) error

	// Recv receives a xDS request from the client.
	Recv() (*envoy_service_discovery.DiscoveryRequest, error)
}
