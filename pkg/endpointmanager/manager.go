// Copyright 2016-2018 Authors of Cilium
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
	"fmt"
	"sync"

	"github.com/cilium/cilium/pkg/endpoint"
	endpointid "github.com/cilium/cilium/pkg/endpoint/id"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy"

	"github.com/prometheus/client_golang/prometheus"
)

var (
	log = logging.DefaultLogger.WithField(logfields.LogSubsys, "endpoint-manager")

	// mutex protects endpoints and endpointsAux
	mutex lock.RWMutex

	// endpoints is the global list of endpoints indexed by ID. mutex must
	// be held to read and write.
	endpoints    = map[uint16]*endpoint.Endpoint{}
	endpointsAux = map[string]*endpoint.Endpoint{}

	// EndpointSynchronizer updates external resources (e.g., Kubernetes) with
	// up-to-date information about endpoints managed by the endpoint manager.
	EndpointSynchronizer EndpointResourceSynchronizer
)

// EndpointResourceSynchronizer is an interface which synchronizes CiliumEndpoint
// resources with Kubernetes.
type EndpointResourceSynchronizer interface {
	RunK8sCiliumEndpointSync(ep *endpoint.Endpoint)
}

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
func Insert(ep *endpoint.Endpoint) {
	// No need to check liveness as an endpoint can only be deleted via the
	// API after it has been inserted into the manager.
	ep.UnconditionalRLock()
	mutex.Lock()

	endpoints[ep.ID] = ep
	updateReferences(ep)

	mutex.Unlock()
	ep.RUnlock()

	if EndpointSynchronizer != nil {
		EndpointSynchronizer.RunK8sCiliumEndpointSync(ep)
	}
}

// Lookup looks up the endpoint by prefix id
func Lookup(id string) (*endpoint.Endpoint, error) {
	mutex.RLock()
	defer mutex.RUnlock()

	prefix, eid, err := endpointid.ParsePrefix(id)
	if err != nil {
		return nil, err
	}

	switch prefix {
	case endpointid.CiliumLocalIdPrefix:
		n, err := endpointid.ParseCiliumID(id)
		if err != nil {
			return nil, err
		}
		return lookupCiliumID(uint16(n)), nil

	case endpointid.CiliumGlobalIdPrefix:
		return nil, ErrUnsupportedID

	case endpointid.ContainerIdPrefix:
		return lookupContainerID(eid), nil

	case endpointid.DockerEndpointPrefix:
		return lookupDockerEndpoint(eid), nil

	case endpointid.ContainerNamePrefix:
		return lookupDockerContainerName(eid), nil

	case endpointid.PodNamePrefix:
		return lookupPodNameLocked(eid), nil

	case endpointid.IPv4Prefix:
		return lookupIPv4(eid), nil

	default:
		return nil, ErrInvalidPrefix{InvalidPrefix: prefix.String()}
	}
}

// LookupCiliumID looks up endpoint by endpoint ID
func LookupCiliumID(id uint16) *endpoint.Endpoint {
	mutex.RLock()
	ep := lookupCiliumID(id)
	mutex.RUnlock()
	return ep
}

// LookupContainerID looks up endpoint by Docker ID
func LookupContainerID(id string) *endpoint.Endpoint {
	mutex.RLock()
	ep := lookupContainerID(id)
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

// LookupPodName looks up endpoint by namespace + pod name
func LookupPodName(name string) *endpoint.Endpoint {
	mutex.RLock()
	ep := lookupPodNameLocked(name)
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

	if ep.ContainerID != "" {
		delete(endpointsAux, endpointid.NewID(endpointid.ContainerIdPrefix, ep.ContainerID))
	}

	if ep.DockerEndpointID != "" {
		delete(endpointsAux, endpointid.NewID(endpointid.DockerEndpointPrefix, ep.DockerEndpointID))
	}

	if ep.IPv4.String() != "" {
		delete(endpointsAux, endpointid.NewID(endpointid.IPv4Prefix, ep.IPv4.String()))
	}

	if ep.ContainerName != "" {
		delete(endpointsAux, endpointid.NewID(endpointid.ContainerNamePrefix, ep.ContainerName))
	}

	if podName := ep.GetK8sNamespaceAndPodNameLocked(); podName != "" {
		delete(endpointsAux, endpointid.NewID(endpointid.PodNamePrefix, podName))
	}
}

// RemoveAll removes all endpoints from the global maps.
func RemoveAll() {
	mutex.Lock()
	defer mutex.Unlock()
	endpoints = map[uint16]*endpoint.Endpoint{}
	endpointsAux = map[string]*endpoint.Endpoint{}
}

// lookupCiliumID looks up endpoint by endpoint ID
func lookupCiliumID(id uint16) *endpoint.Endpoint {
	if ep, ok := endpoints[id]; ok {
		return ep
	}
	return nil
}

func lookupDockerEndpoint(id string) *endpoint.Endpoint {
	if ep, ok := endpointsAux[endpointid.NewID(endpointid.DockerEndpointPrefix, id)]; ok {
		return ep
	}
	return nil
}

func lookupPodNameLocked(name string) *endpoint.Endpoint {
	if ep, ok := endpointsAux[endpointid.NewID(endpointid.PodNamePrefix, name)]; ok {
		return ep
	}
	return nil
}

func lookupDockerContainerName(name string) *endpoint.Endpoint {
	if ep, ok := endpointsAux[endpointid.NewID(endpointid.ContainerNamePrefix, name)]; ok {
		return ep
	}
	return nil
}

func lookupIPv4(ipv4 string) *endpoint.Endpoint {
	if ep, ok := endpointsAux[endpointid.NewID(endpointid.IPv4Prefix, ipv4)]; ok {
		return ep
	}
	return nil
}

func lookupContainerID(id string) *endpoint.Endpoint {
	if ep, ok := endpointsAux[endpointid.NewID(endpointid.ContainerIdPrefix, id)]; ok {
		return ep
	}
	return nil
}

// UpdateReferences updates the mappings of various values to their corresponding
// endpoints, such as ContainerID, Docker Container Name, Pod Name, etc.
func updateReferences(ep *endpoint.Endpoint) {
	if ep.ContainerID != "" {
		endpointsAux[endpointid.NewID(endpointid.ContainerIdPrefix, ep.ContainerID)] = ep
	}

	if ep.DockerEndpointID != "" {
		endpointsAux[endpointid.NewID(endpointid.DockerEndpointPrefix, ep.DockerEndpointID)] = ep
	}

	if ep.IPv4.String() != "" {
		endpointsAux[endpointid.NewID(endpointid.IPv4Prefix, ep.IPv4.String())] = ep
	}

	if ep.ContainerName != "" {
		endpointsAux[endpointid.NewID(endpointid.ContainerNamePrefix, ep.ContainerName)] = ep
	}

	if podName := ep.GetK8sNamespaceAndPodNameLocked(); podName != "" {
		endpointsAux[endpointid.NewID(endpointid.PodNamePrefix, podName)] = ep
	}
}

// RegenerateAllEndpoints calls a SetStateLocked for each endpoint and
// regenerates if state transaction is valid. During this process, the endpoint
// list is locked and cannot be modified.
// Returns a waiting group that can be used to know when all the endpoints are
// regenerated.
func RegenerateAllEndpoints(owner endpoint.Owner, regenMetadata *endpoint.ExternalRegenerationMetadata) *sync.WaitGroup {
	var wg sync.WaitGroup

	eps := GetEndpoints()
	wg.Add(len(eps))

	log.Infof("regenerating all endpoints due to %s", regenMetadata.Reason)
	for _, ep := range eps {
		go func(ep *endpoint.Endpoint, wg *sync.WaitGroup) {
			if err := ep.LockAlive(); err != nil {
				log.WithError(err).Warnf("Endpoint disappeared while queued to be regenerated: %s", regenMetadata.Reason)
				ep.LogStatus(endpoint.Policy, endpoint.Failure, "Error while handling policy updates for endpoint: "+err.Error())
			} else {
				regen := ep.SetStateLocked(endpoint.StateWaitingToRegenerate, fmt.Sprintf("Triggering endpoint regeneration due to %s", regenMetadata.Reason))
				ep.Unlock()
				if regen {
					// Regenerate logs status according to the build success/failure
					<-ep.Regenerate(owner, regenMetadata)
				}
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
		if !e.Options.IsEnabled(option.ConntrackLocal) {
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

// AddEndpoint takes the prepared endpoint object and starts managing it.
func AddEndpoint(owner endpoint.Owner, ep *endpoint.Endpoint, reason string) (err error) {
	alwaysEnforce := policy.GetPolicyEnabled() == option.AlwaysEnforce
	ep.SetIngressPolicyEnabled(alwaysEnforce)
	ep.SetEgressPolicyEnabled(alwaysEnforce)

	// Regenerate immediately if ready or waiting for identity
	if err := ep.LockAlive(); err != nil {
		return err
	}
	build := false
	state := ep.GetStateLocked()

	// We can only trigger regeneration of endpoints if the endpoint is in a
	// state where it can regenerate. See endpoint.SetStateLocked().
	if state == endpoint.StateReady {
		ep.SetStateLocked(endpoint.StateWaitingToRegenerate, reason)
		build = true
	}
	ep.Unlock()

	if build {
		if err := ep.RegenerateWait(owner, reason); err != nil {
			return err
		}
	}

	Insert(ep)
	ep.InsertEvent()

	return nil
}

// WaitForEndpointsAtPolicyRev waits for all endpoints which existed at the time
// this function is called to be at a given policy revision.
// New endpoints appearing while waiting are ignored.
func WaitForEndpointsAtPolicyRev(ctx context.Context, rev uint64) error {
	eps := GetEndpoints()
	for i := range eps {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-eps[i].WaitForPolicyRevision(ctx, rev):
			if ctx.Err() != nil {
				return ctx.Err()
			}
		}
	}
	return nil
}
