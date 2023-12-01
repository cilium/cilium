// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package endpointmanager

import (
	"context"
	"maps"

	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/node"
)

// GetHostEndpoint returns the host endpoint.
func (mgr *endpointManager) GetHostEndpoint() *endpoint.Endpoint {
	mgr.mutex.RLock()
	defer mgr.mutex.RUnlock()
	for _, ep := range mgr.endpoints {
		if ep.IsHost() {
			return ep
		}
	}
	return nil
}

// HostEndpointExists returns true if the host endpoint exists.
func (mgr *endpointManager) HostEndpointExists() bool {
	return mgr.GetHostEndpoint() != nil
}

func (mgr *endpointManager) startNodeLabelsObserver(old map[string]string) {
	mgr.localNodeStore.Observe(context.Background(), func(ln node.LocalNode) {
		if maps.Equal(old, ln.Labels) {
			return
		}

		mgr.updateHostEndpointLabels(old, ln.Labels)
		old = ln.Labels
	}, func(error) { /* Executed only when we are shutting down */ })
}

func (mgr *endpointManager) updateHostEndpointLabels(oldNodeLabels, newNodeLabels map[string]string) {
	nodeEP := mgr.GetHostEndpoint()
	if nodeEP == nil {
		log.Error("Host endpoint not found")
		return
	}

	err := nodeEP.UpdateLabelsFrom(oldNodeLabels, newNodeLabels, labels.LabelSourceK8s)
	if err != nil {
		// An error can only occur if either the endpoint is terminating, or the
		// old labels are not found. Both are impossible, hence there's no point
		// in retrying.
		log.WithError(err).Error("Unable to update host endpoint labels")
		return
	}
}
