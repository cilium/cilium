// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package endpointmanager

import (
	"context"
	"maps"

	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/labelsfilter"
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
		oldIdtyLabels, _ := labelsfilter.Filter(labels.Map2Labels(old, labels.LabelSourceK8s))
		newIdtyLabels, _ := labelsfilter.Filter(labels.Map2Labels(ln.Labels, labels.LabelSourceK8s))
		if maps.Equal(oldIdtyLabels.K8sStringMap(), newIdtyLabels.K8sStringMap()) {
			log.Debug("Host endpoint identity labels unchanged, skipping labels update")
			return
		}

		if mgr.updateHostEndpointLabels(old, ln.Labels) {
			// Endpoint's label update logic rejects a request if any of the old labels are
			// not present in the endpoint manager's state. So, overwrite old labels only if
			// the update is successful to avoid node labels being outdated indefinitely (GH-29649).
			old = ln.Labels
		}

	}, func(error) { /* Executed only when we are shutting down */ })
}

// updateHostEndpointLabels updates the local node labels in the endpoint manager.
// Returns true if the update is successful.
func (mgr *endpointManager) updateHostEndpointLabels(oldNodeLabels, newNodeLabels map[string]string) bool {
	nodeEP := mgr.GetHostEndpoint()
	if nodeEP == nil {
		log.Error("Host endpoint not found")
		return false
	}

	if err := nodeEP.UpdateLabelsFrom(oldNodeLabels, newNodeLabels, labels.LabelSourceK8s); err != nil {
		// An error can only occur if either the endpoint is terminating, or the
		// old labels are not found. Both are impossible, hence there's no point
		// in retrying.
		log.WithError(err).Error("Unable to update host endpoint labels")
		return false
	}
	return true
}
