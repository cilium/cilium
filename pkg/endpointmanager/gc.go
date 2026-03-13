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

// markAndSweep performs a two-phase garbage collection of endpoints using the
// configured EndpointChecker.
//
// 1) Sweep all endpoints marked as requiring GC during the previous iteration.
// 2) Mark all endpoints that require GC. Do not GC these endpoints this round.
//
// This way, if there is a temporary condition that will be resolved by other
// components in the system, then we will not flag warnings about the system
// getting out-of-sync. Additionally, by sweeping first and then marking, we
// avoid the issue where endpoint IDs get reused between mark and sweep phases,
// which could lead to accidentally deleting newly created healthy endpoints.
func (mgr *endpointManager) markAndSweep(ctx context.Context) error {
	gcCandidates := make(map[uint16]struct{})
	toSweep := make([]*endpoint.Endpoint, 0, len(mgr.markedEndpoints))

	mgr.mutex.RLock()
	for eid, ep := range mgr.endpoints {
		if err := mgr.checkHealth(ep); err != nil {
			// Only collect perviously marked endpoints for cleanup.
			if _, ok := mgr.markedEndpoints[eid]; ok {
				toSweep = append(toSweep, ep)
			} else {
				gcCandidates[eid] = struct{}{}
			}
		}
	}
	mgr.mutex.RUnlock()

	mgr.markedEndpoints = gcCandidates
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
