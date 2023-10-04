// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package endpointmanager

import (
	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/labels"
)

// GetIngressEndpoint returns the ingress endpoint.
func (mgr *endpointManager) GetIngressEndpoint() *endpoint.Endpoint {
	mgr.mutex.RLock()
	defer mgr.mutex.RUnlock()
	for _, ep := range mgr.endpoints {
		if ep.HasLabels(labels.LabelIngress) {
			return ep
		}
	}
	return nil
}

// IngressEndpointExists returns true if the ingress endpoint exists.
func (mgr *endpointManager) IngressEndpointExists() bool {
	return mgr.GetIngressEndpoint() != nil
}
