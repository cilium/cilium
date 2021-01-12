// Copyright 2021 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package endpointmanager

import (
	"context"

	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/logging/logfields"

	"github.com/sirupsen/logrus"
)

// EndpointCheckerFunc can verify whether an endpoint is currently healthy.
type EndpointCheckerFunc func(*endpoint.Endpoint) error

// markAndSweep performs a two-phase garbage collection of endpoints using the
// configured EndpointChecker.
//
// 1) Mark all endpoints that require GC. Do not GC these endpoints this round.
// 2) Sweep all endpoints marked as requiring GC during the previous iteration.
//
// This way, if there is a temporary condition that will be resolved by other
// components in the system, then we will not flag warnings about the system
// getting out-of-sync.
func (mgr *EndpointManager) markAndSweep(ctx context.Context) error {
	marked := mgr.markEndpoints()

	mgr.mutex.Lock()
	toSweep := mgr.markedEndpoints
	mgr.markedEndpoints = marked
	mgr.mutex.Unlock()

	// Avoid returning an error which would cause the calling controller to
	// re-run the garbage collection more frequently than the RunInterval.
	mgr.sweepEndpoints(toSweep)
	return nil
}

// markEndpoints runs all endpoints in the manager against the configured
// EndpointChecker and returns a slice of endpoint ids that require garbage
// collection.
func (mgr *EndpointManager) markEndpoints() []uint16 {
	mgr.mutex.RLock()
	defer mgr.mutex.RUnlock()

	needsGC := make([]uint16, 0, len(mgr.endpoints))
	for eid, ep := range mgr.endpoints {
		if err := mgr.checkHealth(ep); err != nil {
			needsGC = append(needsGC, eid)
		}
	}
	return needsGC
}

// sweepEndpoints iterates through the specified list of endpoints marked for
// deletion and attempts to garbage-collect them if they still exist.
func (mgr *EndpointManager) sweepEndpoints(markedEndpoints []uint16) {
	toSweep := make([]*endpoint.Endpoint, 0, len(markedEndpoints))

	// 'markedEndpoints' were marked during the previous mark round, so
	// they may no longer be valid endpoints. Narrow the list to only the
	// endpoints that remain. Then, release the lock so RemoveEndpoint()
	// below can independently grab it.
	mgr.mutex.RLock()
	for _, id := range markedEndpoints {
		if ep, ok := mgr.endpoints[id]; ok {
			toSweep = append(toSweep, ep)
		}
	}
	mgr.mutex.RUnlock()

	for _, ep := range toSweep {
		log.WithFields(logrus.Fields{
			logfields.EndpointID:  ep.StringID(),
			logfields.ContainerID: ep.GetShortContainerID(),
			logfields.K8sPodName:  ep.GetK8sNamespaceAndPodName(),
			logfields.URL:         "https://github.com/kubernetes/kubernetes/issues/86944",
		}).Warning("Stray endpoint found. You may be affected by upstream Kubernetes issue #86944.")
		errs := mgr.RemoveEndpoint(ep, endpoint.DeleteConfig{
			NoIPRelease: ep.DatapathConfiguration.ExternalIpam,
		})
		if len(errs) > 0 {
			scopedLog := log.WithField(logfields.EndpointID, ep.GetID())
			for _, err := range errs {
				scopedLog.WithError(err).Warn("Ignoring error while garbage collecting endpoint")
			}
		}
	}
}
