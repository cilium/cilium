// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package endpointmanager

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"net/netip"
	"sync"

	"github.com/cilium/hive/cell"
	"github.com/sirupsen/logrus"

	"github.com/cilium/cilium/pkg/completion"
	"github.com/cilium/cilium/pkg/controller"
	"github.com/cilium/cilium/pkg/endpoint"
	endpointid "github.com/cilium/cilium/pkg/endpoint/id"
	"github.com/cilium/cilium/pkg/endpoint/regeneration"
	"github.com/cilium/cilium/pkg/identity/cache"
	"github.com/cilium/cilium/pkg/ipcache"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/mcastmanager"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/metrics/metric"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/time"
)

var (
	log         = logging.DefaultLogger.WithField(logfields.LogSubsys, "endpoint-manager")
	metricsOnce sync.Once
	launchTime  = 30 * time.Second

	endpointGCControllerGroup = controller.NewGroup("endpoint-gc")
)

// endpointManager is a structure designed for containing state about the
// collection of locally running endpoints.
type endpointManager struct {
	health cell.Health

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

	// subscribers are notified when events occur in the endpointManager.
	subscribers map[Subscriber]struct{}

	// checkHealth supports endpoint garbage collection by verifying the health
	// of an endpoint.
	checkHealth EndpointCheckerFunc

	// deleteEndpoint is the function used to remove the endpoint from the
	// endpointManager and clean it up. Always set to RemoveEndpoint.
	deleteEndpoint endpointDeleteFunc

	// A mark-and-sweep garbage collector may operate on the endpoint list.
	// This is configured via WithPeriodicEndpointGC() and will mark
	// endpoints for removal on one run of the controller, then in the
	// subsequent controller run will remove the endpoints.
	markedEndpoints []uint16

	// controllers associated with the endpoint manager.
	controllers *controller.Manager

	policyMapPressure *policyMapPressure

	// locaNodeStore allows to retrieve information and observe changes about
	// the local node.
	localNodeStore *node.LocalNodeStore

	// Allocator for local endpoint identifiers.
	epIDAllocator *epIDAllocator
}

// endpointDeleteFunc is used to abstract away concrete Endpoint Delete
// functionality from endpoint management for testing purposes.
type endpointDeleteFunc func(*endpoint.Endpoint, endpoint.DeleteConfig) []error

// New creates a new endpointManager.
func New(epSynchronizer EndpointResourceSynchronizer, lns *node.LocalNodeStore, health cell.Health) *endpointManager {
	mgr := endpointManager{
		health:                       health,
		endpoints:                    make(map[uint16]*endpoint.Endpoint),
		endpointsAux:                 make(map[string]*endpoint.Endpoint),
		mcastManager:                 mcastmanager.New(option.Config.IPv6MCastDevice),
		EndpointResourceSynchronizer: epSynchronizer,
		subscribers:                  make(map[Subscriber]struct{}),
		controllers:                  controller.NewManager(),
		localNodeStore:               lns,
		epIDAllocator:                newEPIDAllocator(),
	}
	mgr.deleteEndpoint = mgr.removeEndpoint
	mgr.policyMapPressure = newPolicyMapPressure()
	return &mgr
}

// WithPeriodicEndpointGC runs a controller to periodically garbage collect
// endpoints that match the specified EndpointCheckerFunc.
func (mgr *endpointManager) WithPeriodicEndpointGC(ctx context.Context, checkHealth EndpointCheckerFunc, interval time.Duration) *endpointManager {
	mgr.checkHealth = checkHealth
	mgr.controllers.UpdateController("endpoint-gc",
		controller.ControllerParams{
			Group:       endpointGCControllerGroup,
			DoFunc:      mgr.markAndSweep,
			RunInterval: interval,
			Context:     ctx,
			Health:      mgr.health.NewScope("endpoint-gc"),
		})
	return mgr
}

// waitForProxyCompletions blocks until all proxy changes have been completed.
func waitForProxyCompletions(proxyWaitGroup *completion.WaitGroup) error {
	err := proxyWaitGroup.Context().Err()
	if err != nil {
		return fmt.Errorf("context cancelled before waiting for proxy updates: %w", err)
	}

	start := time.Now()
	log.Debug("Waiting for proxy updates to complete...")
	err = proxyWaitGroup.Wait()
	if err != nil {
		return fmt.Errorf("proxy updates failed: %w", err)
	}
	log.Debug("Wait time for proxy updates: ", time.Since(start))

	return nil
}

// UpdatePolicyMaps returns a WaitGroup which is signaled upon once all endpoints
// have had their PolicyMaps updated against the Endpoint's desired policy state.
//
// Endpoints will wait on the 'notifyWg' parameter before updating policy maps.
func (mgr *endpointManager) UpdatePolicyMaps(ctx context.Context, notifyWg *sync.WaitGroup) *sync.WaitGroup {
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
			if err := ep.ApplyPolicyMapChanges(proxyWaitGroup); err != nil && !errors.Is(err, endpoint.ErrNotAlive) {
				ep.Logger("endpointmanager").WithError(err).Warning("Failed to apply policy map changes. These will be re-applied in future updates.")
			}
			epWG.Done()
		}(ep)
	}

	return &wg
}

// InitMetrics hooks the endpointManager into the metrics subsystem. This can
// only be done once, globally, otherwise the metrics library will panic.
func (mgr *endpointManager) InitMetrics(registry *metrics.Registry) {
	if option.Config.DryMode {
		return
	}
	metricsOnce.Do(func() { // Endpoint is a function used to collect this metric. We cannot
		// increment/decrement a gauge since we invoke Remove gratuitously and that
		// would result in negative counts.
		// It must be thread-safe.

		metrics.Endpoint = metric.NewGaugeFunc(metric.GaugeOpts{
			Namespace: metrics.Namespace,
			Name:      "endpoint",
			Help:      "Number of endpoints managed by this agent",
		},
			func() float64 { return float64(len(mgr.GetEndpoints())) },
		)
		registry.MustRegister(metrics.Endpoint)
	})
}

// allocateID checks if the ID can be reused. If it cannot, returns an error.
// If an ID of 0 is provided, a new ID is allocated. If a new ID cannot be
// allocated, returns an error.
func (mgr *endpointManager) allocateID(currID uint16) (uint16, error) {
	var newID uint16
	if currID != 0 {
		if err := mgr.epIDAllocator.reuse(currID); err != nil {
			return 0, fmt.Errorf("unable to reuse endpoint ID: %w", err)
		}
		newID = currID
	} else {
		id := mgr.epIDAllocator.allocate()
		if id == uint16(0) {
			return 0, fmt.Errorf("no more endpoint IDs available")
		}
		newID = id
	}

	return newID, nil
}

func (mgr *endpointManager) removeIDLocked(currID uint16) {
	delete(mgr.endpoints, currID)
}

// RemoveID removes the id from the endpoints map in the endpointManager.
func (mgr *endpointManager) RemoveID(currID uint16) {
	mgr.mutex.Lock()
	defer mgr.mutex.Unlock()
	mgr.removeIDLocked(currID)
}

// Lookup looks up the endpoint by prefix id
func (mgr *endpointManager) Lookup(id string) (*endpoint.Endpoint, error) {
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
		if n > endpointid.MaxEndpointID {
			return nil, fmt.Errorf("%d: endpoint ID too large", n)
		}
		return mgr.lookupCiliumID(uint16(n)), nil

	case endpointid.CiliumGlobalIdPrefix:
		return nil, ErrUnsupportedID

	case endpointid.CNIAttachmentIdPrefix:
		return mgr.lookupCNIAttachmentID(eid), nil

	case endpointid.ContainerIdPrefix:
		return mgr.lookupContainerID(eid), nil

	case endpointid.DockerEndpointPrefix:
		return mgr.lookupDockerEndpoint(eid), nil

	case endpointid.ContainerNamePrefix:
		return mgr.lookupDockerContainerName(eid), nil

	case endpointid.PodNamePrefix:
		return mgr.lookupPodNameLocked(eid), nil

	case endpointid.CEPNamePrefix:
		return mgr.lookupCEPNameLocked(eid), nil

	case endpointid.IPv4Prefix:
		return mgr.lookupIPv4(eid), nil

	case endpointid.IPv6Prefix:
		return mgr.lookupIPv6(eid), nil

	default:
		return nil, ErrInvalidPrefix{InvalidPrefix: prefix.String()}
	}
}

// LookupCiliumID looks up endpoint by endpoint ID
func (mgr *endpointManager) LookupCiliumID(id uint16) *endpoint.Endpoint {
	mgr.mutex.RLock()
	ep := mgr.lookupCiliumID(id)
	mgr.mutex.RUnlock()
	return ep
}

// LookupCNIAttachmentID looks up endpoint by CNI attachment ID
func (mgr *endpointManager) LookupCNIAttachmentID(id string) *endpoint.Endpoint {
	mgr.mutex.RLock()
	ep := mgr.lookupCNIAttachmentID(id)
	mgr.mutex.RUnlock()
	return ep
}

// LookupIPv4 looks up endpoint by IPv4 address
func (mgr *endpointManager) LookupIPv4(ipv4 string) *endpoint.Endpoint {
	mgr.mutex.RLock()
	ep := mgr.lookupIPv4(ipv4)
	mgr.mutex.RUnlock()
	return ep
}

// LookupIPv6 looks up endpoint by IPv6 address
func (mgr *endpointManager) LookupIPv6(ipv6 string) *endpoint.Endpoint {
	mgr.mutex.RLock()
	ep := mgr.lookupIPv6(ipv6)
	mgr.mutex.RUnlock()
	return ep
}

// LookupIP looks up endpoint by IP address
func (mgr *endpointManager) LookupIP(ip netip.Addr) (ep *endpoint.Endpoint) {
	ipStr := ip.Unmap().String()
	mgr.mutex.RLock()
	if ip.Is4() {
		ep = mgr.lookupIPv4(ipStr)
	} else {
		ep = mgr.lookupIPv6(ipStr)
	}
	mgr.mutex.RUnlock()
	return ep
}

// LookupCEPName looks up an endpoint by its K8s namespace + cep name
func (mgr *endpointManager) LookupCEPName(namespacedName string) *endpoint.Endpoint {
	mgr.mutex.RLock()
	ep := mgr.lookupCEPNameLocked(namespacedName)
	mgr.mutex.RUnlock()
	return ep
}

// GetEndpointsByPodName looks up endpoints by namespace + pod name
func (mgr *endpointManager) GetEndpointsByPodName(namespacedName string) []*endpoint.Endpoint {
	mgr.mutex.RLock()
	defer mgr.mutex.RUnlock()
	eps := make([]*endpoint.Endpoint, 0, 1)
	for _, ep := range mgr.endpoints {
		if ep.GetK8sNamespaceAndPodName() == namespacedName {
			eps = append(eps, ep)
		}
	}

	return eps
}

// GetEndpointsByContainerID looks up endpoints by container ID
func (mgr *endpointManager) GetEndpointsByContainerID(containerID string) []*endpoint.Endpoint {
	mgr.mutex.RLock()
	defer mgr.mutex.RUnlock()

	eps := make([]*endpoint.Endpoint, 0, 1)
	for _, ep := range mgr.endpoints {
		if ep.GetContainerID() == containerID {
			eps = append(eps, ep)
		}
	}
	return eps
}

// ReleaseID releases the ID of the specified endpoint from the endpointManager.
// Returns an error if the ID cannot be released.
func (mgr *endpointManager) ReleaseID(ep *endpoint.Endpoint) error {
	return mgr.epIDAllocator.release(ep.ID)
}

// unexpose removes the endpoint from the endpointmanager, so subsequent
// lookups will no longer find the endpoint.
func (mgr *endpointManager) unexpose(ep *endpoint.Endpoint) {
	defer ep.Close()
	identifiers := ep.Identifiers()

	previousState := ep.GetState()

	mgr.mutex.Lock()
	defer mgr.mutex.Unlock()

	// This must be done before the ID is released for the endpoint!
	mgr.removeIDLocked(ep.ID)
	mgr.mcastManager.RemoveAddress(ep.IPv6)

	// We haven't yet allocated the ID for a restoring endpoint, so no
	// need to release it.
	if previousState != endpoint.StateRestoring {
		if err := mgr.ReleaseID(ep); err != nil {
			log.WithError(err).WithFields(logrus.Fields{
				"state":                   previousState,
				logfields.CNIAttachmentID: identifiers[endpointid.CNIAttachmentIdPrefix],
				logfields.CEPName:         identifiers[endpointid.CEPNamePrefix],
			}).Warning("Unable to release endpoint ID")
		}
	}

	mgr.removeReferencesLocked(identifiers)
}

// removeEndpoint stops the active handling of events by the specified endpoint,
// and prevents the endpoint from being globally acccessible via other packages.
func (mgr *endpointManager) removeEndpoint(ep *endpoint.Endpoint, conf endpoint.DeleteConfig) []error {
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
func (mgr *endpointManager) RemoveEndpoint(ep *endpoint.Endpoint, conf endpoint.DeleteConfig) []error {
	return mgr.deleteEndpoint(ep, conf)
}

// lookupCiliumID looks up endpoint by endpoint ID
func (mgr *endpointManager) lookupCiliumID(id uint16) *endpoint.Endpoint {
	if ep, ok := mgr.endpoints[id]; ok {
		return ep
	}
	return nil
}

func (mgr *endpointManager) lookupDockerEndpoint(id string) *endpoint.Endpoint {
	if ep, ok := mgr.endpointsAux[endpointid.NewID(endpointid.DockerEndpointPrefix, id)]; ok {
		return ep
	}
	return nil
}

func (mgr *endpointManager) lookupPodNameLocked(name string) *endpoint.Endpoint {
	if ep, ok := mgr.endpointsAux[endpointid.NewID(endpointid.PodNamePrefix, name)]; ok {
		return ep
	}
	return nil
}

func (mgr *endpointManager) lookupCEPNameLocked(name string) *endpoint.Endpoint {
	if ep, ok := mgr.endpointsAux[endpointid.NewID(endpointid.CEPNamePrefix, name)]; ok {
		return ep
	}
	return nil
}

func (mgr *endpointManager) lookupDockerContainerName(name string) *endpoint.Endpoint {
	if ep, ok := mgr.endpointsAux[endpointid.NewID(endpointid.ContainerNamePrefix, name)]; ok {
		return ep
	}
	return nil
}

func (mgr *endpointManager) lookupIPv4(ipv4 string) *endpoint.Endpoint {
	if ep, ok := mgr.endpointsAux[endpointid.NewID(endpointid.IPv4Prefix, ipv4)]; ok {
		return ep
	}
	return nil
}

func (mgr *endpointManager) lookupIPv6(ipv6 string) *endpoint.Endpoint {
	if ep, ok := mgr.endpointsAux[endpointid.NewID(endpointid.IPv6Prefix, ipv6)]; ok {
		return ep
	}
	return nil
}

func (mgr *endpointManager) lookupContainerID(id string) *endpoint.Endpoint {
	if ep, ok := mgr.endpointsAux[endpointid.NewID(endpointid.ContainerIdPrefix, id)]; ok {
		return ep
	}
	return nil
}

func (mgr *endpointManager) lookupCNIAttachmentID(id string) *endpoint.Endpoint {
	if ep, ok := mgr.endpointsAux[endpointid.NewID(endpointid.CNIAttachmentIdPrefix, id)]; ok {
		return ep
	}
	return nil
}

// updateIDReferenceLocked updates the endpoints map in the endpointManager for
// the given Endpoint.
func (mgr *endpointManager) updateIDReferenceLocked(ep *endpoint.Endpoint) {
	if ep == nil {
		return
	}
	mgr.endpoints[ep.ID] = ep
}

func (mgr *endpointManager) updateReferencesLocked(ep *endpoint.Endpoint, identifiers endpointid.Identifiers) {
	for k := range identifiers {
		id := endpointid.NewID(k, identifiers[k])
		mgr.endpointsAux[id] = ep
	}
}

// UpdateReferences updates maps the contents of mappings to the specified endpoint.
func (mgr *endpointManager) UpdateReferences(ep *endpoint.Endpoint) error {
	mgr.mutex.Lock()
	defer mgr.mutex.Unlock()

	identifiers := ep.Identifiers()
	mgr.updateReferencesLocked(ep, identifiers)

	return nil
}

// removeReferencesLocked removes the mappings from the endpointmanager.
func (mgr *endpointManager) removeReferencesLocked(identifiers endpointid.Identifiers) {
	for prefix := range identifiers {
		id := endpointid.NewID(prefix, identifiers[prefix])
		delete(mgr.endpointsAux, id)
	}
}

// RegenerateAllEndpoints calls a setState for each endpoint and
// regenerates if state transaction is valid. During this process, the endpoint
// list is locked and cannot be modified.
// Returns a waiting group that can be used to know when all the endpoints are
// regenerated.
func (mgr *endpointManager) RegenerateAllEndpoints(regenMetadata *regeneration.ExternalRegenerationMetadata) *sync.WaitGroup {
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
func (mgr *endpointManager) OverrideEndpointOpts(om option.OptionMap) {
	for _, ep := range mgr.GetEndpoints() {
		if _, err := ep.ApplyOpts(om); err != nil && !errors.Is(err, endpoint.ErrNotAlive) {
			log.WithError(err).WithFields(logrus.Fields{
				"ep": ep.GetID(),
			}).Error("Override endpoint options failed")
		}
	}
}

// HasGlobalCT returns true if the endpoints have a global CT, false otherwise.
func (mgr *endpointManager) HasGlobalCT() bool {
	eps := mgr.GetEndpoints()
	for _, e := range eps {
		if !e.Options.IsEnabled(option.ConntrackLocal) {
			return true
		}
	}
	return false
}

// GetEndpoints returns a slice of all endpoints present in endpoint manager.
func (mgr *endpointManager) GetEndpoints() []*endpoint.Endpoint {
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
func (mgr *endpointManager) GetPolicyEndpoints() map[policy.Endpoint]struct{} {
	mgr.mutex.RLock()
	eps := make(map[policy.Endpoint]struct{}, len(mgr.endpoints))
	for _, ep := range mgr.endpoints {
		eps[ep] = struct{}{}
	}
	mgr.mutex.RUnlock()
	return eps
}

func (mgr *endpointManager) expose(ep *endpoint.Endpoint) error {
	newID, err := mgr.allocateID(ep.ID)
	if err != nil {
		return err
	}

	mgr.mutex.Lock()
	// Get a copy of the identifiers before exposing the endpoint
	identifiers := ep.Identifiers()
	ep.PolicyMapPressureUpdater = mgr.policyMapPressure
	ep.Start(newID)
	mgr.mcastManager.AddAddress(ep.IPv6)
	mgr.updateIDReferenceLocked(ep)
	mgr.updateReferencesLocked(ep, identifiers)
	mgr.mutex.Unlock()

	ep.InitEndpointHealth(mgr.health)
	mgr.RunK8sCiliumEndpointSync(ep, ep.GetReporter("cep-k8s-sync"))

	return nil
}

// RestoreEndpoint exposes the specified endpoint to other subsystems via the
// manager.
func (mgr *endpointManager) RestoreEndpoint(ep *endpoint.Endpoint) error {
	err := mgr.expose(ep)
	if err != nil {
		return err
	}
	mgr.mutex.RLock()
	// Unlock the mutex after reading the subscribers list to not block
	// endpoint restore operation. This could potentially mean that
	// subscribers are called even after they've unsubscribed. However,
	// consumers unsubscribe during the tear down phase so the restore
	// callbacks may likely not race with unsubscribe calls.
	subscribers := maps.Clone(mgr.subscribers)
	mgr.mutex.RUnlock()
	for s := range subscribers {
		s.EndpointRestored(ep)
	}

	return nil
}

// AddEndpoint takes the prepared endpoint object and starts managing it.
func (mgr *endpointManager) AddEndpoint(owner regeneration.Owner, ep *endpoint.Endpoint) (err error) {
	if ep.ID != 0 {
		return fmt.Errorf("Endpoint ID is already set to %d", ep.ID)
	}

	// Updating logger to re-populate pod fields
	// when endpoint and its logger are created pod details are not populated
	// and all subsequent logs have empty pod details like ip addresses, k8sPodName
	// this update will populate pod details in logger
	ep.UpdateLogger(map[string]interface{}{
		logfields.ContainerID: ep.GetShortContainerID(),
		logfields.IPv4:        ep.GetIPv4Address(),
		logfields.IPv6:        ep.GetIPv6Address(),
		logfields.K8sPodName:  ep.GetK8sNamespaceAndPodName(),
		logfields.CEPName:     ep.GetK8sNamespaceAndCEPName(),
	})

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

func (mgr *endpointManager) AddIngressEndpoint(
	ctx context.Context,
	owner regeneration.Owner,
	policyGetter policyRepoGetter,
	ipcache *ipcache.IPCache,
	proxy endpoint.EndpointProxy,
	allocator cache.IdentityAllocator,
) error {
	ep, err := endpoint.CreateIngressEndpoint(owner, policyGetter, ipcache, proxy, allocator)
	if err != nil {
		return err
	}

	if err := mgr.AddEndpoint(owner, ep); err != nil {
		return err
	}

	ep.InitWithIngressLabels(ctx, launchTime)

	return nil
}

func (mgr *endpointManager) AddHostEndpoint(
	ctx context.Context,
	owner regeneration.Owner,
	policyGetter policyRepoGetter,
	ipcache *ipcache.IPCache,
	proxy endpoint.EndpointProxy,
	allocator cache.IdentityAllocator,
) error {
	ep, err := endpoint.CreateHostEndpoint(owner, policyGetter, ipcache, proxy, allocator)
	if err != nil {
		return err
	}

	if err := mgr.AddEndpoint(owner, ep); err != nil {
		return err
	}

	node.SetEndpointID(ep.GetID())

	mgr.initHostEndpointLabels(ctx, ep)

	return nil
}

type policyRepoGetter interface {
	GetPolicyRepository() *policy.Repository
}

// InitHostEndpointLabels initializes the host endpoint's labels with the
// node's known labels.
func (mgr *endpointManager) InitHostEndpointLabels(ctx context.Context) {
	ep := mgr.GetHostEndpoint()
	if ep == nil {
		log.Error("Attempted to init host endpoint labels but host endpoint not set.")
		return
	}

	mgr.initHostEndpointLabels(ctx, ep)
}

func (mgr *endpointManager) initHostEndpointLabels(ctx context.Context, ep *endpoint.Endpoint) {
	// initHostEndpointLabels is executed by the daemon start hook, and
	// at that point we are guaranteed that the local node has already
	// been initialized, and this Get() operation returns immediately.
	ln, err := mgr.localNodeStore.Get(ctx)
	if err != nil {
		// An error may be returned here only if the context has been canceled,
		// which means that we are already shutting down. In that case, let's
		// just return immediately, as we cannot do anything else.
		return
	}

	ep.InitWithNodeLabels(ctx, ln.Labels, launchTime)

	// Start the observer to keep the labels synchronized in case they change
	mgr.startNodeLabelsObserver(ln.Labels)
}

// WaitForEndpointsAtPolicyRev waits for all endpoints which existed at the time
// this function is called to be at a given policy revision.
// New endpoints appearing while waiting are ignored.
func (mgr *endpointManager) WaitForEndpointsAtPolicyRev(ctx context.Context, rev uint64) error {
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
func (mgr *endpointManager) CallbackForEndpointsAtPolicyRev(ctx context.Context, rev uint64, done func(time.Time)) error {
	eps := mgr.GetEndpoints()
	for i := range eps {
		eps[i].WaitForPolicyRevision(ctx, rev, done)
	}
	return nil
}

// EndpointExists returns whether the endpoint with id exists.
func (mgr *endpointManager) EndpointExists(id uint16) bool {
	return mgr.LookupCiliumID(id) != nil
}

// GetEndpointNetnsCookieByIP returns the netns cookie for the passed endpoint with ip address if found.
func (mgr *endpointManager) GetEndpointNetnsCookieByIP(ip netip.Addr) (uint64, error) {
	ep := mgr.LookupIP(ip)
	if ep == nil {
		return 0, fmt.Errorf("endpoint not found by ip %v", ip)
	}

	return ep.NetNsCookie, nil
}
