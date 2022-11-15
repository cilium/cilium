package cache

import (
	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/k8s"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/option"
)

// newEndpoints returns a new Endpoints
func newEndpoints() *Endpoints {
	return &Endpoints{
		Backends: map[cmtypes.AddrCluster]*k8s.Backend{},
	}
}

// filterEndpoints filters local endpoints by using k8s service heuristics.
// For now it only implements the topology aware hints.
func (sc *serviceCache) filterEndpoints(localEndpoints *Endpoints, svc *Service) *Endpoints {
	if !option.Config.EnableServiceTopology || svc == nil || !svc.TopologyAware {
		return localEndpoints
	}

	if sc.selfNodeZoneLabel == "" {
		// The node doesn't have the zone label set, so we cannot filter endpoints
		// by zone. Therefore, return all endpoints.
		return localEndpoints
	}

	if svc.TrafficPolicy == loadbalancer.SVCTrafficPolicyLocal {
		// According to https://kubernetes.io/docs/concepts/services-networking/topology-aware-hints/#constraints:
		// """
		// Topology Aware Hints are not used when either externalTrafficPolicy or
		// internalTrafficPolicy is set to Local on a Service.
		// """
		return localEndpoints
	}

	filteredEndpoints := &Endpoints{Backends: map[cmtypes.AddrCluster]*k8s.Backend{}}

	for key, backend := range localEndpoints.Backends {
		if len(backend.HintsForZones) == 0 {
			return localEndpoints
		}

		for _, hint := range backend.HintsForZones {
			if hint == sc.selfNodeZoneLabel {
				filteredEndpoints.Backends[key] = backend
				break
			}
		}
	}

	if len(filteredEndpoints.Backends) == 0 {
		// Fallback to all endpoints if there is no any which could match
		// the zone. Otherwise, the node will start dropping requests to
		// the service.
		return localEndpoints
	}

	return filteredEndpoints
}

// FIXME where should these live
const (
	serviceAffinityNone   = ""
	serviceAffinityLocal  = "local"
	serviceAffinityRemote = "remote"
)

// correlateEndpoints builds a combined Endpoints of the local endpoints and
// all external endpoints if the service is marked as a global service. Also
// returns a boolean that indicates whether the service is ready to be plumbed,
// this is true if:
// A local endpoints resource is present. Regardless whether the
//
//	endpoints resource contains actual backends or not.
//
// OR Remote endpoints exist which correlate to the service.
func (sc *serviceCache) correlateEndpoints(id ServiceID) (*Endpoints, bool) {
	endpoints := newEndpoints()

	localEndpoints := sc.endpoints[id].GetEndpoints()
	svc, svcFound := sc.services[id]

	hasLocalEndpoints := localEndpoints != nil
	if hasLocalEndpoints {
		localEndpoints = sc.filterEndpoints(localEndpoints, svc)

		for ip, e := range localEndpoints.Backends {
			e.Preferred = svcFound && svc.IncludeExternal && svc.ServiceAffinity == serviceAffinityLocal
			endpoints.Backends[ip] = e
		}
	}

	/* FIXME
	if svcFound && svc.IncludeExternal {
		externalEndpoints, hasExternalEndpoints := sc.externalEndpoints[id]
		if hasExternalEndpoints {
			// remote cluster endpoints already contain all Endpoints from all
			// EndpointSlices so no need to search the endpoints of a particular
			// EndpointSlice.
			for clusterName, remoteClusterEndpoints := range externalEndpoints.endpoints {
				for ip, e := range remoteClusterEndpoints.Backends {
					if _, ok := endpoints.Backends[ip]; ok {
						sc.params.Log.WithFields(logrus.Fields{
							logfields.K8sSvcName:   id.Name,
							logfields.K8sNamespace: id.Namespace,
							logfields.IPAddr:       ip,
							"cluster":              clusterName,
						}).Warning("Conflicting service backend IP")
					} else {
						e.Preferred = svc.ServiceAffinity == serviceAffinityRemote
						endpoints.Backends[ip] = e
					}
				}
			}
		}
	}*/

	// Report the service as ready if a local endpoints object exists or if
	// external endpoints have been identified
	return endpoints, hasLocalEndpoints || len(endpoints.Backends) > 0
}
