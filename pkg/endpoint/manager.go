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

package endpoint

import (
	"fmt"
	"sync"

	"github.com/cilium/cilium/pkg/config"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/prometheus/client_golang/prometheus"
)

var (
	// mutex protects endpoints and endpointsAux
	mutex lock.RWMutex

	// endpoints is the global list of endpoints indexed by ID. mutex must
	// be held to read and write.
	endpoints    = map[uint16]*Endpoint{}
	endpointsAux = map[string]*Endpoint{}
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
func Insert(ep *Endpoint) {
	mutex.Lock()
	endpoints[ep.ID] = ep
	updateReferences(ep)
	mutex.Unlock()
}

// Lookup looks up the endpoint by prefix id
func Lookup(id string) (*Endpoint, error) {
	mutex.RLock()
	defer mutex.RUnlock()

	prefix, eid, err := ParseID(id)
	if err != nil {
		return nil, err
	}

	switch prefix {
	case CiliumLocalIdPrefix:
		n, err := ParseCiliumID(id)
		if err != nil {
			return nil, err
		}
		return lookupCiliumID(uint16(n)), nil

	case CiliumGlobalIdPrefix:
		return nil, fmt.Errorf("Unsupported id format for now")

	case ContainerIdPrefix:
		return lookupDockerID(eid), nil

	case DockerEndpointPrefix:
		return lookupDockerEndpoint(eid), nil

	case ContainerNamePrefix:
		return lookupDockerContainerName(eid), nil

	case PodNamePrefix:
		return lookupPodNameLocked(eid), nil

	case IPv4Prefix:
		return lookupIPv4(eid), nil

	default:
		return nil, fmt.Errorf("Unknown endpoint prefix %s", prefix)
	}
}

// LookupCiliumID looks up endpoint by endpoint ID
func LookupCiliumID(id uint16) *Endpoint {
	mutex.RLock()
	ep := lookupCiliumID(id)
	mutex.RUnlock()
	return ep
}

// LookupDockerID looks up endpoint by Docker ID
func LookupDockerID(id string) *Endpoint {
	mutex.RLock()
	ep := lookupDockerID(id)
	mutex.RUnlock()
	return ep
}

// LookupIPv4 looks up endpoint by IPv4 address
func LookupIPv4(ipv4 string) *Endpoint {
	mutex.RLock()
	ep := lookupIPv4(ipv4)
	mutex.RUnlock()
	return ep
}

// UpdateReferences makes an endpoint available by all possible reference
// fields as available for this endpoint (containerID, IPv4 address, ...)
// Must be called with ep.Mutex.RLock held.
func UpdateReferences(ep *Endpoint) {
	mutex.Lock()
	defer mutex.Unlock()
	updateReferences(ep)
}

// Remove removes the endpoint from the global maps.
// Must be called with ep.Mutex.RLock held.
func Remove(ep *Endpoint) {
	mutex.Lock()
	defer mutex.Unlock()
	delete(endpoints, ep.ID)

	if ep.DockerID != "" {
		delete(endpointsAux, NewID(ContainerIdPrefix, ep.DockerID))
	}

	if ep.DockerEndpointID != "" {
		delete(endpointsAux, NewID(DockerEndpointPrefix, ep.DockerEndpointID))
	}

	if ep.IPv4.String() != "" {
		delete(endpointsAux, NewID(IPv4Prefix, ep.IPv4.String()))
	}

	if ep.ContainerName != "" {
		delete(endpointsAux, NewID(ContainerNamePrefix, ep.ContainerName))
	}

	if ep.PodName != "" {
		delete(endpointsAux, NewID(PodNamePrefix, ep.PodName))
	}
}

// lookupCiliumID looks up endpoint by endpoint ID
func lookupCiliumID(id uint16) *Endpoint {
	if ep, ok := endpoints[id]; ok {
		return ep
	}
	return nil
}

func lookupDockerEndpoint(id string) *Endpoint {
	if ep, ok := endpointsAux[NewID(DockerEndpointPrefix, id)]; ok {
		return ep
	}
	return nil
}

func lookupPodNameLocked(name string) *Endpoint {
	if ep, ok := endpointsAux[NewID(PodNamePrefix, name)]; ok {
		return ep
	}
	return nil
}

func lookupDockerContainerName(name string) *Endpoint {
	if ep, ok := endpointsAux[NewID(ContainerNamePrefix, name)]; ok {
		return ep
	}
	return nil
}

func lookupIPv4(ipv4 string) *Endpoint {
	if ep, ok := endpointsAux[NewID(IPv4Prefix, ipv4)]; ok {
		return ep
	}
	return nil
}

func lookupDockerID(id string) *Endpoint {
	if ep, ok := endpointsAux[NewID(ContainerIdPrefix, id)]; ok {
		return ep
	}
	return nil
}

func linkContainerID(ep *Endpoint) {
	endpointsAux[NewID(ContainerIdPrefix, ep.DockerID)] = ep
}

// UpdateReferences updates the mappings of various values to their corresponding
// endpoints, such as DockerID, Docker Container Name, Pod Name, etc.
func updateReferences(ep *Endpoint) {
	if ep.DockerID != "" {
		linkContainerID(ep)
	}

	if ep.DockerEndpointID != "" {
		endpointsAux[NewID(DockerEndpointPrefix, ep.DockerEndpointID)] = ep
	}

	if ep.IPv4.String() != "" {
		endpointsAux[NewID(IPv4Prefix, ep.IPv4.String())] = ep
	}

	if ep.ContainerName != "" {
		endpointsAux[NewID(ContainerNamePrefix, ep.ContainerName)] = ep
	}

	if ep.PodName != "" {
		endpointsAux[NewID(PodNamePrefix, ep.PodName)] = ep
	}
}

// TriggerPolicyUpdates calls TriggerPolicyUpdatesLocked for each endpoint and
// regenerates as required. During this process, the endpoint list is locked
// and cannot be modified.
// Returns a waiting group that can be used to know when all the endpoints are
// regenerated.
func TriggerPolicyUpdates(owner Owner) *sync.WaitGroup {
	var wg sync.WaitGroup

	eps := GetEndpoints()
	wg.Add(len(eps))

	for _, ep := range eps {
		go func(ep *Endpoint, wg *sync.WaitGroup) {
			ep.Mutex.Lock()
			policyChanges, ctCleaned, err := ep.TriggerPolicyUpdatesLocked(owner, nil)
			regen := false
			if err == nil && policyChanges {
				// Regenerate only if state transition succeeds
				regen = ep.SetStateLocked(StateWaitingToRegenerate, "Triggering endpoint regeneration due to policy updates")
			}
			ep.Mutex.Unlock()

			if err != nil {
				log.WithError(err).Warn("Error while handling policy updates for endpoint")
				ep.LogStatus(Policy, Failure, "Error while handling policy updates for endpoint: "+err.Error())
			} else {
				// Wait for endpoint CT clean has complete before
				// regenerating endpoint.
				ctCleaned.Wait()
				if !policyChanges {
					ep.LogStatusOK(Policy, "Endpoint policy update skipped because no changes were needed")
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
		globalCT := e.Consumable != nil && !e.Opts.IsEnabled(config.OptionConntrackLocal)
		e.RUnlock()
		if globalCT {
			return true
		}
	}
	return false
}

// GetEndpoints returns a slice of all endpoints present in endpoint manager.
func GetEndpoints() []*Endpoint {
	mutex.RLock()
	eps := make([]*Endpoint, 0, len(endpoints))
	for _, ep := range endpoints {
		eps = append(eps, ep)
	}
	mutex.RUnlock()
	return eps
}
