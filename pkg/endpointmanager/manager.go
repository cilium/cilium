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

	log "github.com/sirupsen/logrus"
)

var (
	// Mutex protects Endpoints and endpointsAux
	//
	// Warning: This lock may not be taken while an individual endpoint
	// lock is being held. If you require to hold both, then the global
	// endpointmanager lock must always be acquired first.
	Mutex lock.RWMutex

	// Endpoints is the global list of endpoints indexed by ID. Mutex must
	// be held to read and write.
	//
	// FIXME: This is currently exported, as more code moves from daemon
	// into pkg/endpoint, we might be able to unexport this
	Endpoints    = map[uint16]*endpoint.Endpoint{}
	endpointsAux = map[string]*endpoint.Endpoint{}
)

// LookupCiliumIDLocked looks up endpoint by endpoint ID with Mutex held
func LookupCiliumIDLocked(id uint16) *endpoint.Endpoint {
	if ep, ok := Endpoints[id]; ok {
		return ep
	}
	return nil
}

// LookupCiliumID looks up endpoint by endpoint ID
func LookupCiliumID(id uint16) *endpoint.Endpoint {
	Mutex.Lock()
	defer Mutex.Unlock()

	return LookupCiliumIDLocked(id)
}

func lookupDockerEndpointLocked(id string) *endpoint.Endpoint {
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

func lookupDockerContainerNameLocked(name string) *endpoint.Endpoint {
	if ep, ok := endpointsAux[endpoint.NewID(endpoint.ContainerNamePrefix, name)]; ok {
		return ep
	}
	return nil
}

// LookupDockerID looks up endpoint by Docker ID
func LookupDockerID(id string) *endpoint.Endpoint {
	Mutex.Lock()
	defer Mutex.Unlock()

	return LookupDockerIDLocked(id)
}

func lookupIPv4Locked(ipv4 string) *endpoint.Endpoint {
	if ep, ok := endpointsAux[endpoint.NewID(endpoint.IPv4Prefix, ipv4)]; ok {
		return ep
	}
	return nil
}

// LookupIPv4 looks up endpoint by IPv4 address
func LookupIPv4(ipv4 string) *endpoint.Endpoint {
	Mutex.Lock()
	defer Mutex.Unlock()

	return lookupIPv4Locked(ipv4)
}

// LookupDockerIDLocked is identical to LookupDockerID() but with
// endpointmanager.Mutex already held
func LookupDockerIDLocked(id string) *endpoint.Endpoint {
	if ep, ok := endpointsAux[endpoint.NewID(endpoint.ContainerIdPrefix, id)]; ok {
		return ep
	}
	return nil
}

func linkContainerID(ep *endpoint.Endpoint) {
	endpointsAux[endpoint.NewID(endpoint.ContainerIdPrefix, ep.DockerID)] = ep
}

// LinkContainerID links an endpoint and makes it searchable by Docker ID.
// Mutex must be held
func LinkContainerID(ep *endpoint.Endpoint) {
	linkContainerID(ep)
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

	if ep.PodName != "" {
		endpointsAux[endpoint.NewID(endpoint.PodNamePrefix, ep.PodName)] = ep
	}
}

// UpdateReferences makes an endpoint available by all possible reference
// fields as available for this endpoint (containerID, IPv4 address, ...)
func UpdateReferences(ep *endpoint.Endpoint) {
	Mutex.Lock()
	defer Mutex.Unlock()

	updateReferences(ep)
}

// Insert inserts the endpoint into the global maps
func Insert(ep *endpoint.Endpoint) {
	Endpoints[ep.ID] = ep
	updateReferences(ep)
}

// RemoveLocked is identical to Remove but with endpointmanager.Mutex already held
func RemoveLocked(ep *endpoint.Endpoint) {
	delete(Endpoints, ep.ID)

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

	if ep.PodName != "" {
		delete(endpointsAux, endpoint.NewID(endpoint.PodNamePrefix, ep.PodName))
	}
}

// Remove removes the endpoint from the global maps
func Remove(ep *endpoint.Endpoint) {
	Mutex.Lock()
	RemoveLocked(ep)
	Mutex.Unlock()
}

// Lookup looks up the endpoint by prefix id
func Lookup(id string) (*endpoint.Endpoint, error) {
	Mutex.RLock()
	defer Mutex.RUnlock()

	return LookupLocked(id)
}

// LookupLocked looks up the endpoint by prefix id with the Mutex already held
func LookupLocked(id string) (*endpoint.Endpoint, error) {
	prefix, eid, err := endpoint.ParseID(id)
	if err != nil {
		return nil, err
	}

	switch prefix {
	case endpoint.CiliumLocalIdPrefix:
		n, _ := endpoint.ParseCiliumID(id)
		return LookupCiliumIDLocked(uint16(n)), nil

	case endpoint.CiliumGlobalIdPrefix:
		return nil, fmt.Errorf("Unsupported id format for now")

	case endpoint.ContainerIdPrefix:
		return LookupDockerIDLocked(eid), nil

	case endpoint.DockerEndpointPrefix:
		return lookupDockerEndpointLocked(eid), nil

	case endpoint.ContainerNamePrefix:
		return lookupDockerContainerNameLocked(eid), nil

	case endpoint.PodNamePrefix:
		return lookupPodNameLocked(eid), nil

	case endpoint.IPv4Prefix:
		return lookupIPv4Locked(eid), nil

	default:
		return nil, fmt.Errorf("Unknown endpoint prefix %s", prefix)
	}
}

// TriggerPolicyUpdates calls TriggerPolicyUpdates for each endpoint and
// regenerates as required. During this process, the endpoint list is locked
// and cannot be modified.
// Returns a waiting group that can be used to know when all the endpoints are
// regenerated.
func TriggerPolicyUpdates(owner endpoint.Owner) *sync.WaitGroup {
	var wg sync.WaitGroup

	Mutex.RLock()

	wg.Add(len(Endpoints))

	for k := range Endpoints {
		go func(ep *endpoint.Endpoint, wg *sync.WaitGroup) {
			policyChanges, err := ep.TriggerPolicyUpdates(owner)
			if err != nil {
				log.WithError(err).Warn("Error while handling policy updates for endpoint")
				ep.LogStatus(endpoint.Policy, endpoint.Failure, err.Error())
			} else {
				ep.LogStatusOK(endpoint.Policy, "Policy regenerated")
			}
			if policyChanges {
				<-ep.Regenerate(owner)
			}
			wg.Done()
		}(Endpoints[k], &wg)
	}

	Mutex.RUnlock()

	return &wg
}
