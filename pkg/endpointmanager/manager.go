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
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/cilium/cilium/pkg/addressing"
	"github.com/cilium/cilium/pkg/completion"
	"github.com/cilium/cilium/pkg/endpoint"
	endpointid "github.com/cilium/cilium/pkg/endpoint/id"
	"github.com/cilium/cilium/pkg/endpoint/regeneration"
	"github.com/cilium/cilium/pkg/endpointmanager/idallocator"
	"github.com/cilium/cilium/pkg/identity/cache"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/labelsfilter"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/mcastmanager"
	"github.com/cilium/cilium/pkg/metrics"
	monitorAPI "github.com/cilium/cilium/pkg/monitor/api"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/sirupsen/logrus"
)

var (
	log         = logging.DefaultLogger.WithField(logfields.LogSubsys, "endpoint-manager")
	metricsOnce sync.Once
	launchTime  = 30 * time.Second
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

	// mcastManager handles IPv6 multicast group join/leave for pods. This is required for the
	// node to receive ICMPv6 NDP messages, especially NS (Neighbor Solicitation) message, so
	// pod's IPv6 address is discoverable.
	mcastManager *mcastmanager.MCastManager

	// EndpointSynchronizer updates external resources (e.g., Kubernetes) with
	// up-to-date information about endpoints managed by the endpoint manager.
	EndpointResourceSynchronizer
}

// EndpointResourceSynchronizer is an interface which synchronizes CiliumEndpoint
// resources with Kubernetes.
type EndpointResourceSynchronizer interface {
	RunK8sCiliumEndpointSync(ep *endpoint.Endpoint, conf endpoint.EndpointStatusConfiguration)
	DeleteK8sCiliumEndpointSync(e *endpoint.Endpoint)
}

// NewEndpointManager creates a new EndpointManager.
func NewEndpointManager(epSynchronizer EndpointResourceSynchronizer) *EndpointManager {
	mgr := EndpointManager{
		endpoints:                    make(map[uint16]*endpoint.Endpoint),
		endpointsAux:                 make(map[string]*endpoint.Endpoint),
		mcastManager:                 mcastmanager.New(option.Config.IPv6MCastDevice),
		EndpointResourceSynchronizer: epSynchronizer,
	}

	return &mgr
}

// waitForProxyCompletions blocks until all proxy changes have been completed.
func waitForProxyCompletions(proxyWaitGroup *completion.WaitGroup) error {
	err := proxyWaitGroup.Context().Err()
	if err != nil {
		return fmt.Errorf("context cancelled before waiting for proxy updates: %s", err)
	}

	start := time.Now()
	log.Debug("Waiting for proxy updates to complete...")
	err = proxyWaitGroup.Wait()
	if err != nil {
		return fmt.Errorf("proxy updates failed: %s", err)
	}
	log.Debug("Wait time for proxy updates: ", time.Since(start))

	return nil
}

// UpdatePolicyMaps returns a WaitGroup which is signaled upon once all endpoints
// have had their PolicyMaps updated against the Endpoint's desired policy state.
func (mgr *EndpointManager) UpdatePolicyMaps(ctx context.Context) *sync.WaitGroup {
	var epWG sync.WaitGroup
	var wg sync.WaitGroup

	proxyWaitGroup := completion.NewWaitGroup(ctx)

	eps := mgr.GetEndpoints()
	epWG.Add(len(eps))
	wg.Add(1)

	// This is in a goroutine to allow the caller to proceed with other tasks before waiting for the ACKs to complete
	go func() {
		// Wait for all the eps to have applied policy map
		// changes before waiting for the changes to be ACKed
		epWG.Wait()
		if err := waitForProxyCompletions(proxyWaitGroup); err != nil {
			log.WithError(err).Warning("Failed to apply L7 proxy policy changes. These will be re-applied in future updates.")
		}
		wg.Done()
	}()

	// TODO: bound by number of CPUs?
	for _, ep := range eps {
		go func(ep *endpoint.Endpoint) {
			if err := ep.ApplyPolicyMapChanges(proxyWaitGroup); err != nil {
				ep.Logger("endpointmanager").WithError(err).Warning("Failed to apply policy map changes. These will be re-applied in future updates.")
			}
			epWG.Done()
		}(ep)
	}

	return &wg
}

// InitMetrics hooks the EndpointManager into the metrics subsystem. This can
// only be done once, globally, otherwise the metrics library will panic.
func (mgr *EndpointManager) InitMetrics() {
	if option.Config.DryMode {
		return
	}
	metricsOnce.Do(func() { // Endpoint is a function used to collect this metric. We cannot
		// increment/decrement a gauge since we invoke Remove gratuitously and that
		// would result in negative counts.
		// It must be thread-safe.

		metrics.Endpoint = prometheus.NewGaugeFunc(prometheus.GaugeOpts{
			Namespace: metrics.Namespace,
			Name:      "endpoint",
			Help:      "Number of endpoints managed by this agent",
		},
			func() float64 { return float64(len(mgr.GetEndpoints())) },
		)
		metrics.MustRegister(metrics.Endpoint)
	})
}

// AllocateID checks if the ID can be reused. If it cannot, returns an error.
// If an ID of 0 is provided, a new ID is allocated. If a new ID cannot be
// allocated, returns an error.
func (mgr *EndpointManager) AllocateID(currID uint16) (uint16, error) {
	var newID uint16
	if currID != 0 {
		if err := idallocator.Reuse(currID); err != nil {
			return 0, fmt.Errorf("unable to reuse endpoint ID: %s", err)
		}
		newID = currID
	} else {
		id := idallocator.Allocate()
		if id == uint16(0) {
			return 0, fmt.Errorf("no more endpoint IDs available")
		}
		newID = id
	}

	return newID, nil
}

// RemoveID removes the id from the endpoints map in the EndpointManager.
func (mgr *EndpointManager) RemoveID(currID uint16) {
	mgr.mutex.Lock()
	defer mgr.mutex.Unlock()
	delete(mgr.endpoints, currID)
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

// ReleaseID releases the ID of the specified endpoint from the EndpointManager.
// Returns an error if the ID cannot be released.
func (mgr *EndpointManager) ReleaseID(ep *endpoint.Endpoint) error {
	return idallocator.Release(ep.ID)
}

// WaitEndpointRemoved waits until all operations associated with Remove of
// the endpoint have been completed.
// Note: only used for unit tests
func (mgr *EndpointManager) WaitEndpointRemoved(ep *endpoint.Endpoint) {
	<-ep.Unexpose(mgr)
}

// RemoveAll removes all endpoints from the global maps.
func (mgr *EndpointManager) RemoveAll() {
	mgr.mutex.Lock()
	defer mgr.mutex.Unlock()
	idallocator.ReallocatePool()
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

// UpdateIDReference updates the endpoints map in the EndpointManager for
// the given Endpoint.
func (mgr *EndpointManager) UpdateIDReference(ep *endpoint.Endpoint) {
	mgr.mutex.Lock()
	defer mgr.mutex.Unlock()
	if ep == nil {
		return
	}
	mgr.endpoints[ep.ID] = ep
}

// UpdateReferences updates maps the contents of mappings to the specified
// endpoint.
func (mgr *EndpointManager) UpdateReferences(mappings map[endpointid.PrefixType]string, ep *endpoint.Endpoint) {
	mgr.mutex.Lock()
	defer mgr.mutex.Unlock()
	for k := range mappings {
		id := endpointid.NewID(k, mappings[k])
		mgr.endpointsAux[id] = ep

	}
}

// RemoveReferences removes the mappings from the endpointmanager.
func (mgr *EndpointManager) RemoveReferences(mappings map[endpointid.PrefixType]string) {
	mgr.mutex.Lock()
	defer mgr.mutex.Unlock()
	for prefix := range mappings {
		id := endpointid.NewID(prefix, mappings[prefix])
		delete(mgr.endpointsAux, id)
	}
}

// AddIPv6Address notifies an addition of an IPv6 address
func (mgr *EndpointManager) AddIPv6Address(ipv6 addressing.CiliumIPv6) {
	mgr.mcastManager.AddAddress(ipv6)
}

// RemoveAIPv6ddress notifies a removal of an IPv6 address
func (mgr *EndpointManager) RemoveIPv6Address(ipv6 addressing.CiliumIPv6) {
	mgr.mcastManager.RemoveAddress(ipv6)
}

// RegenerateAllEndpoints calls a setState for each endpoint and
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
	ep.SetDefaultConfiguration(false)

	if ep.ID != 0 {
		return fmt.Errorf("Endpoint ID is already set to %d", ep.ID)
	}
	err = ep.Expose(mgr)
	if err != nil {
		return err
	}
	owner.SendNotification(monitorAPI.EndpointCreateMessage(ep))

	return nil
}

func (mgr *EndpointManager) AddHostEndpoint(ctx context.Context, owner regeneration.Owner,
	proxy endpoint.EndpointProxy, allocator cache.IdentityAllocator, reason string, nodeName string) error {
	ep, err := endpoint.CreateHostEndpoint(owner, proxy, allocator)
	if err != nil {
		return err
	}

	if err := mgr.AddEndpoint(owner, ep, reason); err != nil {
		return err
	}

	epLabels := labels.Labels{}
	epLabels.MergeLabels(labels.LabelHost)

	// Initialize with known node labels.
	newLabels := labels.Map2Labels(node.GetLabels(), labels.LabelSourceK8s)
	newIdtyLabels, _ := labelsfilter.Filter(newLabels)
	epLabels.MergeLabels(newIdtyLabels)

	// Give the endpoint a security identity
	newCtx, cancel := context.WithTimeout(ctx, launchTime)
	defer cancel()
	ep.UpdateLabels(newCtx, epLabels, nil, true)
	if errors.Is(newCtx.Err(), context.DeadlineExceeded) {
		log.WithError(newCtx.Err()).Warning("Timed out while updating security identify for host endpoint")
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

// EndpointExists returns whether the endpoint with id exists.
func (mgr *EndpointManager) EndpointExists(id uint16) bool {
	return mgr.LookupCiliumID(id) != nil
}

// GetHostEndpoint returns the host endpoint.
func (mgr *EndpointManager) GetHostEndpoint() *endpoint.Endpoint {
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
func (mgr *EndpointManager) HostEndpointExists() bool {
	return mgr.GetHostEndpoint() != nil
}
