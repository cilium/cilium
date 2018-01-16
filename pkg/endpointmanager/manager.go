// Copyright 2016-2017 Authors of Cilium
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
	"fmt"
	"sync"

	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/prometheus/client_golang/prometheus"
)

var (
	log = logging.DefaultLogger

	// mutex protects endpoints and endpointsAux
	mutex lock.RWMutex

	// endpoints is the global list of endpoints indexed by ID. mutex must
	// be held to read and write.
	endpoints    = map[uint16]*endpoint.Endpoint{}
	endpointsAux = map[string]*endpoint.Endpoint{}
)

func init() {
	// EndpointCount is a function used to collect this metric. We cannot
	// increment/decrement a gauge since we invoke Remove gratuitiously and that
	// would result in negative counts.
	// It must be thread-safe.
	metrics.EndpointCount = prometheus.NewGaugeFunc(prometheus.GaugeOpts{
		Namespace: metrics.Namespace,
		Name:      "endpoint_count",
		Help:      "Number of endpoints managed by this agent",
	},
		func() float64 { return float64(len(GetEndpoints())) },
	)
	metrics.MustRegister(metrics.EndpointCount)
}

// Insert inserts the endpoint into the global maps.
// Must be called with ep.Mutex.RLock held.
func Insert(ep *endpoint.Endpoint) {
	mutex.Lock()
	endpoints[ep.ID] = ep
	updateReferences(ep)
	mutex.Unlock()
}

// Lookup looks up the endpoint by prefix id
func Lookup(id string) (*endpoint.Endpoint, error) {
	mutex.RLock()
	defer mutex.RUnlock()

	prefix, eid, err := endpoint.ParseID(id)
	if err != nil {
		return nil, err
	}

	switch prefix {
	case endpoint.CiliumLocalIdPrefix:
		n, err := endpoint.ParseCiliumID(id)
		if err != nil {
			return nil, err
		}
		return lookupCiliumID(uint16(n)), nil

	case endpoint.CiliumGlobalIdPrefix:
		return nil, fmt.Errorf("Unsupported id format for now")

	case endpoint.ContainerIdPrefix:
		return lookupDockerID(eid), nil

	case endpoint.DockerEndpointPrefix:
		return lookupDockerEndpoint(eid), nil

	case endpoint.ContainerNamePrefix:
		return lookupDockerContainerName(eid), nil

	case endpoint.PodNamePrefix:
		return lookupPodNameLocked(eid), nil

	case endpoint.IPv4Prefix:
		return lookupIPv4(eid), nil

	default:
		return nil, fmt.Errorf("Unknown endpoint prefix %s", prefix)
	}
}

// LookupCiliumID looks up endpoint by endpoint ID
func LookupCiliumID(id uint16) *endpoint.Endpoint {
	mutex.RLock()
	ep := lookupCiliumID(id)
	mutex.RUnlock()
	return ep
}

// LookupDockerID looks up endpoint by Docker ID
func LookupDockerID(id string) *endpoint.Endpoint {
	mutex.RLock()
	ep := lookupDockerID(id)
	mutex.RUnlock()
	return ep
}

// LookupIPv4 looks up endpoint by IPv4 address
func LookupIPv4(ipv4 string) *endpoint.Endpoint {
	mutex.RLock()
	ep := lookupIPv4(ipv4)
	mutex.RUnlock()
	return ep
}

// UpdateReferences makes an endpoint available by all possible reference
// fields as available for this endpoint (containerID, IPv4 address, ...)
// Must be called with ep.Mutex.RLock held.
func UpdateReferences(ep *endpoint.Endpoint) {
	mutex.Lock()
	defer mutex.Unlock()
	updateReferences(ep)
}

// Remove removes the endpoint from the global maps.
// Must be called with ep.Mutex.RLock held.
func Remove(ep *endpoint.Endpoint) {
	mutex.Lock()
	defer mutex.Unlock()
	delete(endpoints, ep.ID)

	if ep.DockerID != "" {
		delete(endpointsAux, endpoint.NewID(endpoint.ContainerIdPrefix, ep.DockerID))
	}

	if ep.DockerEndpointID != "" {
		delete(endpointsAux, endpoint.NewID(endpoint.DockerEndpointPrefix, ep.DockerEndpointID))
	}

	if ep.IPv4.String() != "" {
		delete(endpointsAux, endpoint.NewID(endpoint.IPv4Prefix, ep.IPv4.String()))
	}

	if ep.ContainerName != "" {
		delete(endpointsAux, endpoint.NewID(endpoint.ContainerNamePrefix, ep.ContainerName))
	}

	if podName := ep.GetK8sNamespaceAndPodNameLocked(); podName != "" {
		delete(endpointsAux, endpoint.NewID(endpoint.PodNamePrefix, podName))
	}
}

// lookupCiliumID looks up endpoint by endpoint ID
func lookupCiliumID(id uint16) *endpoint.Endpoint {
	if ep, ok := endpoints[id]; ok {
		return ep
	}
	return nil
}

func lookupDockerEndpoint(id string) *endpoint.Endpoint {
	if ep, ok := endpointsAux[endpoint.NewID(endpoint.DockerEndpointPrefix, id)]; ok {
		return ep
	}
	return nil
}

func lookupPodNameLocked(name string) *endpoint.Endpoint {
	if ep, ok := endpointsAux[endpoint.NewID(endpoint.PodNamePrefix, name)]; ok {
		return ep
	}
	return nil
}

func lookupDockerContainerName(name string) *endpoint.Endpoint {
	if ep, ok := endpointsAux[endpoint.NewID(endpoint.ContainerNamePrefix, name)]; ok {
		return ep
	}
	return nil
}

func lookupIPv4(ipv4 string) *endpoint.Endpoint {
	if ep, ok := endpointsAux[endpoint.NewID(endpoint.IPv4Prefix, ipv4)]; ok {
		return ep
	}
	return nil
}

func lookupDockerID(id string) *endpoint.Endpoint {
	if ep, ok := endpointsAux[endpoint.NewID(endpoint.ContainerIdPrefix, id)]; ok {
		return ep
	}
	return nil
}

func linkContainerID(ep *endpoint.Endpoint) {
	endpointsAux[endpoint.NewID(endpoint.ContainerIdPrefix, ep.DockerID)] = ep
}

// UpdateReferences updates the mappings of various values to their corresponding
// endpoints, such as DockerID, Docker Container Name, Pod Name, etc.
func updateReferences(ep *endpoint.Endpoint) {
	if ep.DockerID != "" {
		linkContainerID(ep)
	}

	if ep.DockerEndpointID != "" {
		endpointsAux[endpoint.NewID(endpoint.DockerEndpointPrefix, ep.DockerEndpointID)] = ep
	}

	if ep.IPv4.String() != "" {
		endpointsAux[endpoint.NewID(endpoint.IPv4Prefix, ep.IPv4.String())] = ep
	}

	if ep.ContainerName != "" {
		endpointsAux[endpoint.NewID(endpoint.ContainerNamePrefix, ep.ContainerName)] = ep
	}

	if podName := ep.GetK8sNamespaceAndPodNameLocked(); podName != "" {
		endpointsAux[endpoint.NewID(endpoint.PodNamePrefix, podName)] = ep
	}
}

// TriggerPolicyUpdates calls TriggerPolicyUpdatesLocked for each endpoint and
// regenerates as required. During this process, the endpoint list is locked
// and cannot be modified.
// Returns a waiting group that can be used to know when all the endpoints are
// regenerated.
func TriggerPolicyUpdates(owner endpoint.Owner) *sync.WaitGroup {
	var wg sync.WaitGroup

	eps := GetEndpoints()
	wg.Add(len(eps))

	for _, ep := range eps {
		go func(ep *endpoint.Endpoint, wg *sync.WaitGroup) {
			ep.Mutex.Lock()
			policyChanges, ctCleaned, err := ep.TriggerPolicyUpdatesLocked(owner, nil)
			regen := false
			if err == nil && policyChanges {
				// Regenerate only if state transition succeeds
				regen = ep.SetStateLocked(endpoint.StateWaitingToRegenerate, "Triggering endpoint regeneration due to policy updates")
			}
			ep.Mutex.Unlock()

			if err != nil {
				log.WithError(err).Warn("Error while handling policy updates for endpoint")
				ep.LogStatus(endpoint.Policy, endpoint.Failure, "Error while handling policy updates for endpoint: "+err.Error())
			} else {
				// Wait for endpoint CT clean has complete before
				// regenerating endpoint.
				ctCleaned.Wait()
				if !policyChanges {
					ep.LogStatusOK(endpoint.Policy, "Endpoint policy update skipped because no changes were needed")
				} else if regen {
					// Regenerate logs status according to the build success/failure
					<-ep.Regenerate(owner, "endpoint policy updated & changes were needed")
				} // else policy changed, but can't regenerate => do not change status
			}
			wg.Done()
		}(ep, &wg)
	}

	return &wg
}

// HasGlobalCT returns true if the endpoints have a global CT, false otherwise.
func HasGlobalCT() bool {
	eps := GetEndpoints()
	for _, e := range eps {
		e.RLock()
		globalCT := e.Consumable != nil && !e.Opts.IsEnabled(endpoint.OptionConntrackLocal)
		e.RUnlock()
		if globalCT {
			return true
		}
	}
	return false
}

// GetEndpoints returns a slice of all endpoints present in endpoint manager.
func GetEndpoints() []*endpoint.Endpoint {
	mutex.RLock()
	eps := make([]*endpoint.Endpoint, 0, len(endpoints))
	for _, ep := range endpoints {
		eps = append(eps, ep)
	}
	mutex.RUnlock()
	return eps
}
