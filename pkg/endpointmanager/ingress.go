// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package endpointmanager

import (
	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/labels"
)

// GetIngressEndpoint returns the ingress endpoint having additionalLabels
func (mgr *endpointManager) GetIngressEndpoint(extra labels.Labels) *endpoint.Endpoint {
	mgr.mutex.RLock()
	defer mgr.mutex.RUnlock()

	all := labels.LabelIngress
	for k, v := range extra {
		all[k] = v
	}

	for _, ep := range mgr.endpoints {
		if ep.HasLabels(all) {
			return ep
		}
	}
	return nil
}

// IngressEndpointExists returns true if the ingress endpoint exists.
func (mgr *endpointManager) IngressEndpointExists(additionalLabels labels.Labels) bool {
	return mgr.GetIngressEndpoint(additionalLabels) != nil
}
