// Copyright 2016-2019 Authors of Cilium
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
	"net"
	"sync"
	"time"

	"github.com/cilium/cilium/pkg/endpoint"
	endpointid "github.com/cilium/cilium/pkg/endpoint/id"
	"github.com/cilium/cilium/pkg/endpoint/regeneration"
	"github.com/cilium/cilium/pkg/eventqueue"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/metrics"
	monitorAPI "github.com/cilium/cilium/pkg/monitor/api"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/sirupsen/logrus"
)

var (
	log         = logging.DefaultLogger.WithField(logfields.LogSubsys, "endpoint-manager")
	metricsOnce sync.Once
)

// EndpointManager is a structure designed for containing state about the
// collection of locally running endpoints.
type EndpointManager struct {
	// mutex protects endpoints and endpointsAux
	mutex lock.RWMutex

	// endpoints is the global list of endpoints indexed by ID. mutex must
	// be held to read and write.
	endpoints    map[uint16]*endpoint.Endpoint
	endpointsAux map[string]*endpoint.Endpoint

	// EndpointSynchronizer updates external resources (e.g., Kubernetes) with
	// up-to-date information about endpoints managed by the endpoint manager.
	endpointSynchronizer EndpointResourceSynchronizer
}

// EndpointResourceSynchronizer is an interface which synchronizes CiliumEndpoint
// resources with Kubernetes.
type EndpointResourceSynchronizer interface {
	RunK8sCiliumEndpointSync(ep *endpoint.Endpoint)
}

// NewEndpointManager creates a new EndpointManager.
func NewEndpointManager(epSynchronizer EndpointResourceSynchronizer) *EndpointManager {
	mgr := EndpointManager{
		endpoints:            make(map[uint16]*endpoint.Endpoint),
		endpointsAux:         make(map[string]*endpoint.Endpoint),
		endpointSynchronizer: epSynchronizer,
	}

	return &mgr
}

// InitMetrics hooks the EndpointManager into the metrics subsystem. This can
// only be done once, globally, otherwise the metrics library will panic.
func (mgr *EndpointManager) InitMetrics() {
	if option.Config.DryMode {
		return
	}
	metricsOnce.Do(func() { // EndpointCount is a function used to collect this metric. We cannot
		// increment/decrement a gauge since we invoke Remove gratuitiously and that
		// would result in negative counts.
		// It must be thread-safe.
		metrics.EndpointCount = prometheus.NewGaugeFunc(prometheus.GaugeOpts{
			Namespace: metrics.Namespace,
			Name:      "endpoint_count",
			Help:      "Number of endpoints managed by this agent",
		},
			func() float64 { return float64(len(mgr.GetEndpoints())) },
		)
		metrics.MustRegister(metrics.EndpointCount)
	})
}

// Insert inserts the endpoint into the maps in the EndpointManager.
func (mgr *EndpointManager) Insert(ep *endpoint.Endpoint) error {
	if ep.ID != 0 {
		if err := endpointid.Reuse(ep.ID); err != nil {
			return fmt.Errorf("unable to reuse endpoint ID: %s", err)
		}
	} else {
		id := endpointid.Allocate()
		if id == uint16(0) {
			return fmt.Errorf("no more endpoint IDs available")
		}
		ep.ID = id

		ep.UpdateLogger(map[string]interface{}{
			logfields.EndpointID: ep.ID,
		})
	}

	// No need to check liveness as an endpoint can only be deleted via the
	// API after it has been inserted into the manager.
	ep.UnconditionalRLock()
	mgr.mutex.Lock()

	// Now that the endpoint has its ID, it can be created with a name based on
	// its ID, and its eventqueue can be safely started. Ensure that it is only
	// started once it is exposed to the endpointmanager so that it will be
	// stopped when the endpoint is removed from the endpointmanager.
	ep.EventQueue = eventqueue.NewEventQueueBuffered(fmt.Sprintf("endpoint-%d", ep.ID), option.Config.EndpointQueueSize)
	ep.EventQueue.Run()

	mgr.endpoints[ep.ID] = ep
	mgr.updateReferences(ep)

	mgr.mutex.Unlock()
	ep.RUnlock()

	if mgr.endpointSynchronizer != nil {
		mgr.endpointSynchronizer.RunK8sCiliumEndpointSync(ep)
	}

	ep.InsertEvent()

	return nil
}

// Lookup looks up the endpoint by prefix id
func (mgr *EndpointManager) Lookup(id string) (*endpoint.Endpoint, error) {
	mgr.mutex.RLock()
	defer mgr.mutex.RUnlock()

	prefix, eid, err := endpointid.Parse(id)
	if err != nil {
		return nil, err
	}

	switch prefix {
	case endpointid.CiliumLocalIdPrefix:
		n, err := endpointid.ParseCiliumID(id)
		if err != nil {
			return nil, err
		}
		return mgr.lookupCiliumID(uint16(n)), nil

	case endpointid.CiliumGlobalIdPrefix:
		return nil, ErrUnsupportedID

	case endpointid.ContainerIdPrefix:
		return mgr.lookupContainerID(eid), nil

	case endpointid.DockerEndpointPrefix:
		return mgr.lookupDockerEndpoint(eid), nil

	case endpointid.ContainerNamePrefix:
		return mgr.lookupDockerContainerName(eid), nil

	case endpointid.PodNamePrefix:
		return mgr.lookupPodNameLocked(eid), nil

	case endpointid.IPv4Prefix:
		return mgr.lookupIPv4(eid), nil

	case endpointid.IPv6Prefix:
		return mgr.lookupIPv6(eid), nil

	default:
		return nil, ErrInvalidPrefix{InvalidPrefix: prefix.String()}
	}
}

// LookupCiliumID looks up endpoint by endpoint ID
func (mgr *EndpointManager) LookupCiliumID(id uint16) *endpoint.Endpoint {
	mgr.mutex.RLock()
	ep := mgr.lookupCiliumID(id)
	mgr.mutex.RUnlock()
	return ep
}

// LookupContainerID looks up endpoint by Docker ID
func (mgr *EndpointManager) LookupContainerID(id string) *endpoint.Endpoint {
	mgr.mutex.RLock()
	ep := mgr.lookupContainerID(id)
	mgr.mutex.RUnlock()
	return ep
}

// LookupIPv4 looks up endpoint by IPv4 address
func (mgr *EndpointManager) LookupIPv4(ipv4 string) *endpoint.Endpoint {
	mgr.mutex.RLock()
	ep := mgr.lookupIPv4(ipv4)
	mgr.mutex.RUnlock()
	return ep
}

// LookupIPv6 looks up endpoint by IPv6 address
func (mgr *EndpointManager) LookupIPv6(ipv6 string) *endpoint.Endpoint {
	mgr.mutex.RLock()
	ep := mgr.lookupIPv6(ipv6)
	mgr.mutex.RUnlock()
	return ep
}

// LookupIP looks up endpoint by IP address
func (mgr *EndpointManager) LookupIP(ip net.IP) (ep *endpoint.Endpoint) {
	addr := ip.String()
	mgr.mutex.RLock()
	if ip.To4() != nil {
		ep = mgr.lookupIPv4(addr)
	} else {
		ep = mgr.lookupIPv6(addr)
	}
	mgr.mutex.RUnlock()
	return ep
}

// LookupPodName looks up endpoint by namespace + pod name
func (mgr *EndpointManager) LookupPodName(name string) *endpoint.Endpoint {
	mgr.mutex.RLock()
	ep := mgr.lookupPodNameLocked(name)
	mgr.mutex.RUnlock()
	return ep
}

// UpdateReferences makes an endpoint available by all possible reference
// fields as available for this endpoint (containerID, IPv4 address, ...)
// Must be called with ep.Mutex.RLock held.
func (mgr *EndpointManager) UpdateReferences(ep *endpoint.Endpoint) {
	mgr.mutex.Lock()
	defer mgr.mutex.Unlock()
	mgr.updateReferences(ep)
}

func (mgr *EndpointManager) releaseID(ep *endpoint.Endpoint) {
	if err := endpointid.Release(ep.ID); err != nil {
		// While restoring, endpoint IDs may not have been reused yet.
		// Failure to release means that the endpoint ID was not reused
		// yet.
		//
		// While endpoint is disconnecting, ID is already available in ID cache.
		//
		// Avoid irritating warning messages.
		state := ep.GetStateLocked()
		if state != endpoint.StateRestoring && state != endpoint.StateDisconnecting {
			log.WithError(err).WithField("state", state).Warning("Unable to release endpoint ID")
		}
	}
}

// WaitEndpointRemoved waits until all operations associated with Remove of
// the endpoint have been completed.
func (mgr *EndpointManager) WaitEndpointRemoved(ep *endpoint.Endpoint) {
	select {
	case <-mgr.Remove(ep):
		return
	}
}

// Remove removes the endpoint from the global maps and releases the node-local
// ID allocated for the endpoint.
// Must be called with ep.Mutex.RLock held. Releasing of the ID of the endpoint
// is done asynchronously. Once the ID of the endpoint is released, the returned
// channel is closed.
func (mgr *EndpointManager) Remove(ep *endpoint.Endpoint) <-chan struct{} {

	epRemoved := make(chan struct{})

	mgr.mutex.Lock()
	defer mgr.mutex.Unlock()

	// This must be done before the ID is released for the endpoint!
	delete(mgr.endpoints, ep.ID)

	go func(ep *endpoint.Endpoint) {

		// The endpoint's EventQueue may not be stopped yet (depending on whether
		// the caller of the EventQueue has stopped it or not). Call it here
		// to be safe so that ep.WaitToBeDrained() does not hang forever.
		ep.EventQueue.Stop()

		// Wait for no more events (primarily regenerations) to be occurring for
		// this endpoint.
		ep.EventQueue.WaitToBeDrained()

		mgr.releaseID(ep)
		close(epRemoved)
	}(ep)

	if ep.ContainerID != "" {
		delete(mgr.endpointsAux, endpointid.NewID(endpointid.ContainerIdPrefix, ep.ContainerID))
	}

	if ep.DockerEndpointID != "" {
		delete(mgr.endpointsAux, endpointid.NewID(endpointid.DockerEndpointPrefix, ep.DockerEndpointID))
	}

	if ep.IPv4.IsSet() {
		delete(mgr.endpointsAux, endpointid.NewID(endpointid.IPv4Prefix, ep.IPv4.String()))
	}

	if ep.IPv6.IsSet() {
		delete(mgr.endpointsAux, endpointid.NewID(endpointid.IPv6Prefix, ep.IPv6.String()))
	}

	if ep.ContainerName != "" {
		delete(mgr.endpointsAux, endpointid.NewID(endpointid.ContainerNamePrefix, ep.ContainerName))
	}

	if podName := ep.GetK8sNamespaceAndPodNameLocked(); podName != "" {
		delete(mgr.endpointsAux, endpointid.NewID(endpointid.PodNamePrefix, podName))
	}
	return epRemoved
}

// RemoveAll removes all endpoints from the global maps.
func (mgr *EndpointManager) RemoveAll() {
	mgr.mutex.Lock()
	defer mgr.mutex.Unlock()
	endpointid.ReallocatePool()
	mgr.endpoints = map[uint16]*endpoint.Endpoint{}
	mgr.endpointsAux = map[string]*endpoint.Endpoint{}
}

// lookupCiliumID looks up endpoint by endpoint ID
func (mgr *EndpointManager) lookupCiliumID(id uint16) *endpoint.Endpoint {
	if ep, ok := mgr.endpoints[id]; ok {
		return ep
	}
	return nil
}

func (mgr *EndpointManager) lookupDockerEndpoint(id string) *endpoint.Endpoint {
	if ep, ok := mgr.endpointsAux[endpointid.NewID(endpointid.DockerEndpointPrefix, id)]; ok {
		return ep
	}
	return nil
}

func (mgr *EndpointManager) lookupPodNameLocked(name string) *endpoint.Endpoint {
	if ep, ok := mgr.endpointsAux[endpointid.NewID(endpointid.PodNamePrefix, name)]; ok {
		return ep
	}
	return nil
}

func (mgr *EndpointManager) lookupDockerContainerName(name string) *endpoint.Endpoint {
	if ep, ok := mgr.endpointsAux[endpointid.NewID(endpointid.ContainerNamePrefix, name)]; ok {
		return ep
	}
	return nil
}

func (mgr *EndpointManager) lookupIPv4(ipv4 string) *endpoint.Endpoint {
	if ep, ok := mgr.endpointsAux[endpointid.NewID(endpointid.IPv4Prefix, ipv4)]; ok {
		return ep
	}
	return nil
}

func (mgr *EndpointManager) lookupIPv6(ipv6 string) *endpoint.Endpoint {
	if ep, ok := mgr.endpointsAux[endpointid.NewID(endpointid.IPv6Prefix, ipv6)]; ok {
		return ep
	}
	return nil
}

func (mgr *EndpointManager) lookupContainerID(id string) *endpoint.Endpoint {
	if ep, ok := mgr.endpointsAux[endpointid.NewID(endpointid.ContainerIdPrefix, id)]; ok {
		return ep
	}
	return nil
}

// UpdateReferences updates the mappings of various values to their corresponding
// endpoints, such as ContainerID, Docker Container Name, Pod Name, etc.
func (mgr *EndpointManager) updateReferences(ep *endpoint.Endpoint) {
	if ep.ContainerID != "" {
		mgr.endpointsAux[endpointid.NewID(endpointid.ContainerIdPrefix, ep.ContainerID)] = ep
	}

	if ep.DockerEndpointID != "" {
		mgr.endpointsAux[endpointid.NewID(endpointid.DockerEndpointPrefix, ep.DockerEndpointID)] = ep
	}

	if ep.IPv4.IsSet() {
		mgr.endpointsAux[endpointid.NewID(endpointid.IPv4Prefix, ep.IPv4.String())] = ep
	}

	if ep.IPv6.IsSet() {
		mgr.endpointsAux[endpointid.NewID(endpointid.IPv6Prefix, ep.IPv6.String())] = ep
	}

	if ep.ContainerName != "" {
		mgr.endpointsAux[endpointid.NewID(endpointid.ContainerNamePrefix, ep.ContainerName)] = ep
	}

	if podName := ep.GetK8sNamespaceAndPodNameLocked(); podName != "" {
		mgr.endpointsAux[endpointid.NewID(endpointid.PodNamePrefix, podName)] = ep
	}
}

// RegenerateAllEndpoints calls a SetStateLocked for each endpoint and
// regenerates if state transaction is valid. During this process, the endpoint
// list is locked and cannot be modified.
// Returns a waiting group that can be used to know when all the endpoints are
// regenerated.
func (mgr *EndpointManager) RegenerateAllEndpoints(regenMetadata *regeneration.ExternalRegenerationMetadata) *sync.WaitGroup {
	var wg sync.WaitGroup

	eps := mgr.GetEndpoints()
	wg.Add(len(eps))

	// Dereference "reason" field outside of logging statement; see
	// https://github.com/sirupsen/logrus/issues/1003.
	reason := regenMetadata.Reason
	log.WithFields(logrus.Fields{"reason": reason}).Info("regenerating all endpoints")
	for _, ep := range eps {
		go func(ep *endpoint.Endpoint) {
			<-ep.RegenerateIfAlive(regenMetadata)
			wg.Done()
		}(ep)
	}

	return &wg
}

// HasGlobalCT returns true if the endpoints have a global CT, false otherwise.
func (mgr *EndpointManager) HasGlobalCT() bool {
	eps := mgr.GetEndpoints()
	for _, e := range eps {
		if !e.Options.IsEnabled(option.ConntrackLocal) {
			return true
		}
	}
	return false
}

// GetEndpoints returns a slice of all endpoints present in endpoint manager.
func (mgr *EndpointManager) GetEndpoints() []*endpoint.Endpoint {
	mgr.mutex.RLock()
	eps := make([]*endpoint.Endpoint, 0, len(mgr.endpoints))
	for _, ep := range mgr.endpoints {
		eps = append(eps, ep)
	}
	mgr.mutex.RUnlock()
	return eps
}

// GetPolicyEndpoints returns a map of all endpoints present in endpoint
// manager as policy.Endpoint interface set for the map key.
func (mgr *EndpointManager) GetPolicyEndpoints() map[policy.Endpoint]struct{} {
	mgr.mutex.RLock()
	eps := make(map[policy.Endpoint]struct{}, len(mgr.endpoints))
	for _, ep := range mgr.endpoints {
		eps[ep] = struct{}{}
	}
	mgr.mutex.RUnlock()
	return eps
}

// AddEndpoint takes the prepared endpoint object and starts managing it.
func (mgr *EndpointManager) AddEndpoint(owner regeneration.Owner, ep *endpoint.Endpoint, reason string) (err error) {
	alwaysEnforce := policy.GetPolicyEnabled() == option.AlwaysEnforce
	ep.SetDesiredIngressPolicyEnabled(alwaysEnforce)
	ep.SetDesiredEgressPolicyEnabled(alwaysEnforce)

	if ep.ID != 0 {
		return fmt.Errorf("Endpoint ID is already set to %d", ep.ID)
	}
	err = mgr.Insert(ep)
	if err != nil {
		return err
	}

	repr, err := monitorAPI.EndpointCreateRepr(ep)
	// Ignore endpoint creation if EndpointCreateRepr != nil
	if err == nil {
		owner.SendNotification(monitorAPI.AgentNotifyEndpointCreated, repr)
	}
	return nil
}

// WaitForEndpointsAtPolicyRev waits for all endpoints which existed at the time
// this function is called to be at a given policy revision.
// New endpoints appearing while waiting are ignored.
func (mgr *EndpointManager) WaitForEndpointsAtPolicyRev(ctx context.Context, rev uint64) error {
	eps := mgr.GetEndpoints()
	for i := range eps {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-eps[i].WaitForPolicyRevision(ctx, rev, nil):
			if ctx.Err() != nil {
				return ctx.Err()
			}
		}
	}
	return nil
}

// CallbackForEndpointsAtPolicyRev registers a callback on all endpoints that
// exist when invoked. It is similar to WaitForEndpointsAtPolicyRevision but
// each endpoint that reaches the desired revision calls 'done' independently.
// The provided callback should not block and generally be lightweight.
func (mgr *EndpointManager) CallbackForEndpointsAtPolicyRev(ctx context.Context, rev uint64, done func(time.Time)) error {
	eps := mgr.GetEndpoints()
	for i := range eps {
		eps[i].WaitForPolicyRevision(ctx, rev, done)
	}
	return nil
}
