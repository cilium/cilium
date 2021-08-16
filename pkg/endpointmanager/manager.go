// SPDX-License-Identifier: Apache-2.0
// Copyright 2016-2019 Authors of Cilium

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
	"github.com/cilium/cilium/pkg/controller"
	"github.com/cilium/cilium/pkg/endpoint"
	endpointid "github.com/cilium/cilium/pkg/endpoint/id"
	"github.com/cilium/cilium/pkg/endpoint/regeneration"
	"github.com/cilium/cilium/pkg/endpointmanager/idallocator"
	"github.com/cilium/cilium/pkg/identity/cache"
	"github.com/cilium/cilium/pkg/k8s/watchers/subscriber"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/mcastmanager"
	"github.com/cilium/cilium/pkg/metrics"
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

// compile time check - EndpointManager must implement
// subscriber.Node
var _ subscriber.Node = (*EndpointManager)(nil)

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

	// subscribers are notified when events occur in the EndpointManager.
	subscribers map[Subscriber]struct{}

	// checkHealth supports endpoint garbage collection by verifying the health
	// of an endpoint.
	checkHealth EndpointCheckerFunc

	// deleteEndpoint is the function used to remove the endpoint from the
	// EndpointManager and clean it up. Always set to RemoveEndpoint.
	deleteEndpoint endpointDeleteFunc

	// A mark-and-sweep garbage collector may operate on the endpoint list.
	// This is configured via WithPeriodicEndpointGC() and will mark
	// endpoints for removal on one run of the controller, then in the
	// subsequent controller run will remove the endpoints.
	markedEndpoints []uint16
}

// EndpointResourceSynchronizer is an interface which synchronizes CiliumEndpoint
// resources with Kubernetes.
type EndpointResourceSynchronizer interface {
	RunK8sCiliumEndpointSync(ep *endpoint.Endpoint, conf endpoint.EndpointStatusConfiguration)
	DeleteK8sCiliumEndpointSync(e *endpoint.Endpoint)
}

// endpointDeleteFunc is used to abstract away concrete Endpoint Delete
// functionality from endpoint management for testing purposes.
type endpointDeleteFunc func(*endpoint.Endpoint, endpoint.DeleteConfig) []error

// NewEndpointManager creates a new EndpointManager.
func NewEndpointManager(epSynchronizer EndpointResourceSynchronizer) *EndpointManager {
	mgr := EndpointManager{
		endpoints:                    make(map[uint16]*endpoint.Endpoint),
		endpointsAux:                 make(map[string]*endpoint.Endpoint),
		mcastManager:                 mcastmanager.New(option.Config.IPv6MCastDevice),
		EndpointResourceSynchronizer: epSynchronizer,
		subscribers:                  make(map[Subscriber]struct{}),
	}
	mgr.deleteEndpoint = mgr.removeEndpoint

	return &mgr
}

// WithPeriodicEndpointGC runs a controller to periodically garbage collect
// endpoints that match the specified EndpointCheckerFunc.
func (mgr *EndpointManager) WithPeriodicEndpointGC(ctx context.Context, checkHealth EndpointCheckerFunc, interval time.Duration) *EndpointManager {
	mgr.checkHealth = checkHealth
	controller.NewManager().UpdateController("endpoint-gc",
		controller.ControllerParams{
			DoFunc:      mgr.markAndSweep,
			RunInterval: interval,
			Context:     ctx,
		})
	return mgr
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
func (mgr *EndpointManager) UpdatePolicyMaps(ctx context.Context, notifyWg *sync.WaitGroup) *sync.WaitGroup {
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
			// Proceed only after all notifications have been delivered to endpoints
			notifyWg.Wait()
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

func (mgr *EndpointManager) removeIDLocked(currID uint16) {
	delete(mgr.endpoints, currID)
}

// RemoveID removes the id from the endpoints map in the EndpointManager.
func (mgr *EndpointManager) RemoveID(currID uint16) {
	mgr.mutex.Lock()
	defer mgr.mutex.Unlock()
	mgr.removeIDLocked(currID)
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

// unexpose removes the endpoint from the endpointmanager, so subsequent
// lookups will no longer find the endpoint.
func (mgr *EndpointManager) unexpose(ep *endpoint.Endpoint) {
	// Fetch the identifiers; this will only fail if the endpoint is
	// already disconnected, in which case we don't need to proceed with
	// the rest of cleaning up the endpoint.
	identifiers, err := ep.Identifiers()
	if err != nil {
		// Already disconnecting
		return
	}
	previousState := ep.GetState()

	mgr.mutex.Lock()
	defer mgr.mutex.Unlock()

	// This must be done before the ID is released for the endpoint!
	mgr.removeIDLocked(ep.ID)
	mgr.RemoveIPv6Address(ep.IPv6)

	// We haven't yet allocated the ID for a restoring endpoint, so no
	// need to release it.
	if previousState != endpoint.StateRestoring {
		if err = mgr.ReleaseID(ep); err != nil {
			log.WithError(err).WithFields(logrus.Fields{
				"state":               previousState,
				logfields.ContainerID: ep.GetShortContainerID(),
				logfields.K8sPodName:  ep.GetK8sNamespaceAndPodName(),
			}).Warning("Unable to release endpoint ID")
		}
	}

	mgr.removeReferencesLocked(identifiers)
}

// removeEndpoint stops the active handling of events by the specified endpoint,
// and prevents the endpoint from being globally acccessible via other packages.
func (mgr *EndpointManager) removeEndpoint(ep *endpoint.Endpoint, conf endpoint.DeleteConfig) []error {
	mgr.unexpose(ep)
	result := ep.Delete(conf)

	mgr.mutex.RLock()
	for s := range mgr.subscribers {
		s.EndpointDeleted(ep, conf)
	}
	mgr.mutex.RUnlock()

	return result
}

// RemoveEndpoint stops the active handling of events by the specified endpoint,
// and prevents the endpoint from being globally acccessible via other packages.
func (mgr *EndpointManager) RemoveEndpoint(ep *endpoint.Endpoint, conf endpoint.DeleteConfig) []error {
	return mgr.deleteEndpoint(ep, conf)
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

// updateIDReferenceLocked updates the endpoints map in the EndpointManager for
// the given Endpoint.
func (mgr *EndpointManager) updateIDReferenceLocked(ep *endpoint.Endpoint) {
	if ep == nil {
		return
	}
	mgr.endpoints[ep.ID] = ep
}

func (mgr *EndpointManager) updateReferencesLocked(ep *endpoint.Endpoint, identifiers endpointid.Identifiers) {
	for k := range identifiers {
		id := endpointid.NewID(k, identifiers[k])
		mgr.endpointsAux[id] = ep
	}
}

// UpdateReferences updates maps the contents of mappings to the specified endpoint.
func (mgr *EndpointManager) UpdateReferences(ep *endpoint.Endpoint) error {
	mgr.mutex.Lock()
	defer mgr.mutex.Unlock()

	identifiers, err := ep.Identifiers()
	if err != nil {
		return err
	}
	mgr.updateReferencesLocked(ep, identifiers)

	return nil
}

// removeReferencesLocked removes the mappings from the endpointmanager.
func (mgr *EndpointManager) removeReferencesLocked(identifiers endpointid.Identifiers) {
	for prefix := range identifiers {
		id := endpointid.NewID(prefix, identifiers[prefix])
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

// OverrideEndpointOpts applies the given options to all endpoints.
func (mgr *EndpointManager) OverrideEndpointOpts(om option.OptionMap) {
	for _, ep := range mgr.GetEndpoints() {
		if _, err := ep.ApplyOpts(om); err != nil && !errors.Is(err, endpoint.ErrEndpointDeleted) {
			log.WithError(err).WithFields(logrus.Fields{
				"ep": ep.GetID(),
			}).Error("Override endpoint options failed")
		}
	}
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

func (mgr *EndpointManager) expose(ep *endpoint.Endpoint) error {
	newID, err := mgr.AllocateID(ep.ID)
	if err != nil {
		return err
	}

	mgr.mutex.Lock()
	// Get a copy of the identifiers before exposing the endpoint
	identifiers := ep.IdentifiersLocked()
	ep.Start(newID)
	mgr.AddIPv6Address(ep.IPv6)
	mgr.updateIDReferenceLocked(ep)
	mgr.updateReferencesLocked(ep, identifiers)
	mgr.mutex.Unlock()

	mgr.RunK8sCiliumEndpointSync(ep, option.Config)

	return nil
}

// RestoreEndpoint exposes the specified endpoint to other subsystems via the
// manager.
func (mgr *EndpointManager) RestoreEndpoint(ep *endpoint.Endpoint) error {
	ep.SetDefaultConfiguration(true)
	return mgr.expose(ep)
}

// AddEndpoint takes the prepared endpoint object and starts managing it.
func (mgr *EndpointManager) AddEndpoint(owner regeneration.Owner, ep *endpoint.Endpoint, reason string) (err error) {
	ep.SetDefaultConfiguration(false)

	if ep.ID != 0 {
		return fmt.Errorf("Endpoint ID is already set to %d", ep.ID)
	}
	err = mgr.expose(ep)
	if err != nil {
		return err
	}

	mgr.mutex.RLock()
	for s := range mgr.subscribers {
		s.EndpointCreated(ep)
	}
	mgr.mutex.RUnlock()

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

	node.SetEndpointID(ep.GetID())

	ep.InitWithNodeLabels(ctx, launchTime)

	return nil
}

// InitHostEndpointLabels initializes the host endpoint's labels with the
// node's known labels.
func (mgr *EndpointManager) InitHostEndpointLabels(ctx context.Context) {
	ep := mgr.GetHostEndpoint()
	ep.InitWithNodeLabels(ctx, launchTime)
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
