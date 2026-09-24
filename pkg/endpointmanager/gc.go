// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package endpointmanager

import (
	"context"

	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

// EndpointCheckerFunc can verify whether an endpoint is currently healthy.
type EndpointCheckerFunc func(*endpoint.Endpoint) error

// isMarkedEndpoint returns whether the endpoint with the given id exists in markedEndpoints
func (mgr *endpointManager) isMarkedEndpoint(id uint16) bool {
	_, ok := mgr.markedEndpoints[id]
	return ok
}

// setMarkedEndpoints replaces markedEndpoints with the provided map.
func (mgr *endpointManager) setMarkedEndpoints(candidates map[uint16]struct{}) {
	mgr.markedEndpoints = candidates
}

// markAndSweep performs a two-phase garbage collection of endpoints using the
// configured EndpointChecker.
//
// 1) Mark all endpoints that require GC. Do not GC these endpoints this round.
// 2) Sweep all endpoints marked as requiring GC during the previous iteration.
//
// This way, if there is a temporary condition that will be resolved by other
// components in the system, then we will not flag warnings about the system
// getting out-of-sync.
func (mgr *endpointManager) markAndSweep(ctx context.Context) error {
	gcCandidates := make(map[uint16]struct{})
	toSweep := []*endpoint.Endpoint{}

	mgr.mutex.RLock()
	for eid, ep := range mgr.endpoints {
		if err := mgr.checkHealth(ep); err != nil {
			// Only collect previously marked endpoints for cleanup.
			if mgr.isMarkedEndpoint(eid) {
				toSweep = append(toSweep, ep)
			} else {
				gcCandidates[eid] = struct{}{}
			}
		}
	}
	mgr.setMarkedEndpoints(gcCandidates)
	mgr.mutex.RUnlock()

	for _, ep := range toSweep {
		mgr.logger.Warn(
			"Stray endpoint found. You may be affected by upstream Kubernetes issue #86944.",
			logfields.EndpointID, ep.StringID(),
			logfields.ContainerID, ep.GetShortContainerID(),
			logfields.K8sPodName, ep.GetK8sNamespaceAndPodName(),
			logfields.CEPName, ep.GetK8sNamespaceAndCEPName(),
			logfields.URL, "https://github.com/kubernetes/kubernetes/issues/86944",
		)
		errs := mgr.RemoveEndpoint(ep, endpoint.DeleteConfig{
			NoIPRelease: ep.DatapathConfiguration.ExternalIpam,
		})
		if len(errs) > 0 {
			for _, err := range errs {
				mgr.logger.Warn("Ignoring error while garbage collecting endpoint",
					logfields.Error, err,
					logfields.EndpointID, ep.GetID(),
				)
			}
		}
	}
	return nil
}
