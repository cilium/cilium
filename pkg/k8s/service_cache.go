// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package k8s

import (
	"context"
	"log/slog"
	"net"
	"net/netip"
	"slices"
	"sync"

	"github.com/cilium/hive/cell"
	"github.com/cilium/statedb"
	"github.com/cilium/stream"
	"github.com/davecgh/go-spew/spew"
	"github.com/spf13/pflag"
	core_v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/sets"

	"github.com/cilium/cilium/pkg/annotation"
	serviceStore "github.com/cilium/cilium/pkg/clustermesh/store"
	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	datapathTables "github.com/cilium/cilium/pkg/datapath/tables"
	"github.com/cilium/cilium/pkg/ip"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/option"
)

// ServiceCacheCell initializes the service cache holds the list of known services
// correlated with the matching endpoints
var ServiceCacheCell = cell.Module(
	"service-cache",
	"Service Cache",

	cell.Config(ServiceCacheConfig{}),
	cell.Provide(newServiceCache),
)

// ServiceCacheConfig defines the configuration options for the service cache.
type ServiceCacheConfig struct {
	EnableServiceTopology bool
}

// Flags implements the cell.Flagger interface.
func (def ServiceCacheConfig) Flags(flags *pflag.FlagSet) {
	flags.Bool("enable-service-topology", def.EnableServiceTopology, "Enable support for service topology aware hints")
}

// CacheAction is the type of action that was performed on the cache
type CacheAction int

const (
	// UpdateService reflects that the service was updated or added
	UpdateService CacheAction = iota

	// DeleteService reflects that the service was deleted
	DeleteService
)

// String returns the cache action as a string
func (c CacheAction) String() string {
	switch c {
	case UpdateService:
		return "service-updated"
	case DeleteService:
		return "service-deleted"
	default:
		return "unknown"
	}
}

// ServiceEvent is emitted via the Events channel of ServiceCache and describes
// the change that occurred in the cache
type ServiceEvent struct {
	// Action is the action that was performed in the cache
	Action CacheAction

	// ID is the identified of the service
	ID ServiceID

	// Service is the service structure
	Service *Service

	// OldService is the old service structure
	OldService *Service

	// Endpoints is the endpoints structured correlated with the service
	Endpoints *Endpoints

	// OldEndpoints is old endpoints structure.
	OldEndpoints *Endpoints

	// SWGDone marks the event as processed. The underlying StoppableWaitGroup
	// provides a mechanism to detect if a service was synchronized with
	// the datapath.
	SWGDone lock.DoneFunc
}

// ServiceNotification is a slimmed down version of a ServiceEvent. In particular
// notifications are optional and thus do not contain a wait group to allow
// producers to wait for the notification to be consumed.
type ServiceNotification struct {
	Action       CacheAction
	ID           ServiceID
	Service      *MinimalService
	OldService   *MinimalService
	Endpoints    *MinimalEndpoints
	OldEndpoints *MinimalEndpoints
}

// MinimalService is a slimmed down version of 'Service'.
// This serves as an intermediate step to switch over to the new load-balancer control-plane,
// allowing implementation of an adapter without having to implement conversions of fields that
// are unused.
// +deepequal-gen=true
// +k8s:deepcopy-gen=true
type MinimalService struct {
	Labels      map[string]string
	Annotations map[string]string
	Selector    map[string]string
}

func (ms *MinimalService) IsExternal() bool {
	return len(ms.Selector) == 0
}

func newMinimalService(svc *Service) *MinimalService {
	if svc == nil {
		return nil
	}
	return &MinimalService{
		Labels:      svc.Labels,
		Annotations: svc.Annotations,
		Selector:    svc.Selector,
	}
}

// MinimalEndpoints is a slimmed down version of 'Endpoints'.
// This serves as an intermediate step to switch over to the new load-balancer control-plane,
// allowing implementation of an adapter without having to implement conversions of fields that
// are unused.
// +deepequal-gen=true
type MinimalEndpoints struct {
	Backends map[cmtypes.AddrCluster]serviceStore.PortConfiguration
}

func (meps *MinimalEndpoints) Prefixes() []netip.Prefix {
	prefixes := make([]netip.Prefix, 0, len(meps.Backends))
	for addrCluster := range meps.Backends {
		addr := addrCluster.Addr()
		prefixes = append(prefixes, netip.PrefixFrom(addr, addr.BitLen()))
	}
	return prefixes
}

func newMinimalEndpoints(eps *Endpoints) *MinimalEndpoints {
	if eps == nil {
		return nil
	}
	meps := &MinimalEndpoints{
		Backends: map[cmtypes.AddrCluster]serviceStore.PortConfiguration{},
	}
	for addrCluster, cfg := range eps.Backends {
		meps.Backends[addrCluster] = cfg.Ports
	}
	return meps
}

// ServiceCache maintains services correlated with the matching endpoints.
type ServiceCache interface {
	// Events may only be read by single consumer. The consumer must acknowledge
	// every event by calling Done() on the ServiceEvent.SWG.
	Events() <-chan ServiceEvent

	// DebugStatus implements debug.StatusObject to provide debug status collection
	// ability
	DebugStatus() string

	// UpdateEndpoints parses a Kubernetes endpoints and adds or updates it in the
	// ServiceCache. Returns the ServiceID unless the Kubernetes endpoints could not
	// be parsed and a bool to indicate whether the endpoints was changed in the
	// cache or not.
	UpdateEndpoints(newEndpoints *Endpoints, swg *lock.StoppableWaitGroup) (ServiceID, *Endpoints)

	// UpdateService parses a Kubernetes service and adds or updates it in the
	// ServiceCache. Returns the ServiceID unless the Kubernetes service could not
	// be parsed and a bool to indicate whether the service was changed in the
	// cache or not.
	UpdateService(k8sSvc *slim_corev1.Service, swg *lock.StoppableWaitGroup) ServiceID

	// DeleteEndpoints parses a Kubernetes endpoints and removes it from the
	// ServiceCache
	DeleteEndpoints(svcID EndpointSliceID, swg *lock.StoppableWaitGroup) ServiceID

	// DeleteService parses a Kubernetes service and removes it from the
	// ServiceCache
	DeleteService(k8sSvc *slim_corev1.Service, swg *lock.StoppableWaitGroup)

	// EnsureService re-emits the event for a service. Used to "reprocess" a service
	// when an override like LocalRedirectPolicy is removed.
	EnsureService(svcID ServiceID, swg *lock.StoppableWaitGroup) bool

	// ForEachService runs the yield callback for each service and its endpoints.
	// If yield returns false, the iteration is terminated early.
	// Services are iterated in random order.
	// The ServiceCache is read-locked during this function call. The passed in
	// Service and Endpoints references are read-only.
	ForEachService(yield func(svcID ServiceID, svc *MinimalService, eps *MinimalEndpoints) bool)

	// GetServiceAddrsWithType returns a map of all the ports and slice of L3n4Addr that are backing the
	// given Service ID with given type. It also returns the number of frontend IPs associated with the service.
	// Note: The returned IPs are with External scope.
	GetServiceAddrsWithType(svcID ServiceID, svcType loadbalancer.SVCType) (map[loadbalancer.FEPortName][]*loadbalancer.L3n4Addr, int)

	// GetServiceFrontendIP returns the frontend IP (aka clusterIP) for the given service with type.
	GetServiceFrontendIP(svcID ServiceID, svcType loadbalancer.SVCType) net.IP

	// LocalServices returns the list of known services that are not marked as
	// global (i.e., whose backends are all in the local cluster only).
	LocalServices() sets.Set[ServiceID]

	// MergeExternalServiceUpdate merges a cluster service of a remote cluster into
	// the local service cache. The service endpoints are stored as external endpoints
	// and are correlated on demand with local services via correlateEndpoints().
	MergeExternalServiceDelete(service *serviceStore.ClusterService, swg *lock.StoppableWaitGroup)

	// MergeExternalServiceUpdate merges a cluster service of a remote cluster into
	// the local service cache. The service endpoints are stored as external endpoints
	// and are correlated on demand with local services via correlateEndpoints().
	MergeExternalServiceUpdate(service *serviceStore.ClusterService, swg *lock.StoppableWaitGroup)

	// ServiceNotification is a slimmed down version of a ServiceEvent. In particular
	// notifications are optional and thus do not contain a wait group to allow
	// producers to wait for the notification to be consumed.
	Notifications() stream.Observable[ServiceNotification]
}

// ServiceCacheImpl is a list of services correlated with the matching endpoints.
// The Events member will receive events as services.
type ServiceCacheImpl struct {
	logger   *slog.Logger
	config   ServiceCacheConfig
	lbConfig loadbalancer.Config

	// Events may only be read by single consumer. The consumer must acknowledge
	// every event by calling Done() on the ServiceEvent.SWG.
	events     <-chan ServiceEvent
	sendEvents chan<- ServiceEvent

	// notifications are multicast and may be received by multiple subscribers.
	notifications         stream.Observable[ServiceNotification]
	emitNotifications     func(ServiceNotification)
	completeNotifications func(error)

	// mutex protects the maps below including the concurrent access of each
	// value.
	mutex    lock.RWMutex
	services map[ServiceID]*Service
	// endpoints maps a service to a map of EndpointSlices. In case the cluster
	// is still using the v1.Endpoints, the key used in the internal map of
	// EndpointSlices is the v1.Endpoint name.
	endpoints map[ServiceID]*EndpointSlices

	// externalEndpoints is a list of additional service backends derived from source other than the local cluster
	externalEndpoints map[ServiceID]externalEndpoints

	selfNodeZoneLabel string

	ServiceMutators []func(svc *slim_corev1.Service, svcInfo *Service)

	db        *statedb.DB
	nodeAddrs statedb.Table[datapathTables.NodeAddress]

	metrics SVCMetrics
}

// NewServiceCache returns a new ServiceCache
func NewServiceCache(logger *slog.Logger, lbConfig loadbalancer.Config, db *statedb.DB, nodeAddrs statedb.Table[datapathTables.NodeAddress], svcMetrics SVCMetrics) *ServiceCacheImpl {
	events := make(chan ServiceEvent, option.Config.K8sServiceCacheSize)
	notifications, emitNotifications, completeNotifications := stream.Multicast[ServiceNotification]()

	return &ServiceCacheImpl{
		logger:                logger,
		db:                    db,
		nodeAddrs:             nodeAddrs,
		services:              map[ServiceID]*Service{},
		endpoints:             map[ServiceID]*EndpointSlices{},
		externalEndpoints:     map[ServiceID]externalEndpoints{},
		events:                events,
		sendEvents:            events,
		notifications:         notifications,
		emitNotifications:     emitNotifications,
		completeNotifications: completeNotifications,
		metrics:               svcMetrics,
		lbConfig:              lbConfig,
	}
}

func newServiceCache(logger *slog.Logger, lc cell.Lifecycle, lbConfig loadbalancer.Config, cfg ServiceCacheConfig, lns *node.LocalNodeStore, db *statedb.DB, nodeAddrs statedb.Table[datapathTables.NodeAddress], metrics SVCMetrics) ServiceCache {
	sc := NewServiceCache(logger, lbConfig, db, nodeAddrs, metrics)
	sc.config = cfg

	var wg sync.WaitGroup
	ctx, cancel := context.WithCancel(context.Background())
	lc.Append(cell.Hook{
		OnStart: func(hc cell.HookContext) error {
			if !cfg.EnableServiceTopology {
				return nil
			}

			// Explicitly get the labels in addition to registering the observer,
			// as otherwise we wouldn't block until the first event is observed.
			ln, err := lns.Get(hc)
			sc.updateSelfNodeLabels(ln.Labels)

			wg.Add(1)
			lns.Observe(ctx, func(ln node.LocalNode) {
				sc.updateSelfNodeLabels(ln.Labels)
			}, func(error) { wg.Done() })

			return err
		},
		OnStop: func(hc cell.HookContext) error {
			sc.completeNotifications(nil)
			cancel()
			wg.Wait()
			return nil
		},
	})

	return sc
}

func (sc *ServiceCacheImpl) Events() <-chan ServiceEvent {
	return sc.events
}

func (s *ServiceCacheImpl) emitEvent(event ServiceEvent) {
	s.sendEvents <- event
	s.emitNotifications(ServiceNotification{
		Action:       event.Action,
		ID:           event.ID,
		Service:      newMinimalService(event.Service),
		OldService:   newMinimalService(event.OldService),
		Endpoints:    newMinimalEndpoints(event.Endpoints),
		OldEndpoints: newMinimalEndpoints(event.OldEndpoints),
	})
}

// Notifications allow multiple subscribers to observe changes to services and
// endpoints.
// Subscribers must register as soon as the service cache is created to ensure
// no notifications are missed, as notifications which happen before a consumer
// is subscribed will be lost.
func (s *ServiceCacheImpl) Notifications() stream.Observable[ServiceNotification] {
	return s.notifications
}

// GetServiceFrontendIP returns the frontend IP (aka clusterIP) for the given service with type.
func (s *ServiceCacheImpl) GetServiceFrontendIP(svcID ServiceID, svcType loadbalancer.SVCType) net.IP {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	svc := s.services[svcID]
	if svc == nil || svc.Type != svcType || len(svc.FrontendIPs) == 0 {
		return nil
	}

	return ip.GetIPFromListByFamily(svc.FrontendIPs, option.Config.EnableIPv4)
}

// GetServiceAddrsWithType returns a map of all the ports and slice of L3n4Addr that are backing the
// given Service ID with given type. It also returns the number of frontend IPs associated with the service.
// Note: The returned IPs are with External scope.
func (s *ServiceCacheImpl) GetServiceAddrsWithType(svcID ServiceID,
	svcType loadbalancer.SVCType) (map[loadbalancer.FEPortName][]*loadbalancer.L3n4Addr, int) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	svc := s.services[svcID]
	if svc == nil || svc.Type != svcType || len(svc.FrontendIPs) == 0 {
		return nil, 0
	}

	addrsByPort := make(map[loadbalancer.FEPortName][]*loadbalancer.L3n4Addr)
	for pName, l4Addr := range svc.Ports {
		addrs := make([]*loadbalancer.L3n4Addr, 0, len(svc.FrontendIPs))
		for _, feIP := range svc.FrontendIPs {
			if isValidServiceFrontendIP(feIP) {
				addrs = append(addrs, loadbalancer.NewL3n4Addr(l4Addr.Protocol, cmtypes.MustAddrClusterFromIP(feIP), l4Addr.Port, loadbalancer.ScopeExternal))
			}
		}

		addrsByPort[pName] = addrs
	}

	return addrsByPort, len(svc.FrontendIPs)
}

// ForEachService runs the yield callback for each service and its endpoints.
// If yield returns false, the iteration is terminated early.
// Services are iterated in random order.
// The ServiceCache is read-locked during this function call. The passed in
// Service and Endpoints references are read-only.
func (s *ServiceCacheImpl) ForEachService(yield func(svcID ServiceID, svc *MinimalService, eps *MinimalEndpoints) bool) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	for svcID, ep := range s.endpoints {
		svc, ok := s.services[svcID]
		if !ok {
			continue
		}
		if !yield(svcID, newMinimalService(svc), newMinimalEndpoints(ep.GetEndpoints())) {
			return
		}
	}
}

// UpdateService parses a Kubernetes service and adds or updates it in the
// ServiceCache. Returns the ServiceID unless the Kubernetes service could not
// be parsed and a bool to indicate whether the service was changed in the
// cache or not.
func (s *ServiceCacheImpl) UpdateService(k8sSvc *slim_corev1.Service, swg *lock.StoppableWaitGroup) ServiceID {
	var addrs []netip.Addr
	if s.nodeAddrs != nil {
		addrs = statedb.Collect(
			statedb.Map(
				// Get all addresses for which NodePort=true
				s.nodeAddrs.List(
					s.db.ReadTxn(),
					datapathTables.NodeAddressNodePortIndex.Query(true)),
				datapathTables.NodeAddress.GetAddr,
			),
		)
	}

	svcID, newService := ParseService(s.logger, s.lbConfig, k8sSvc, addrs)
	if newService == nil {
		return svcID
	}

	for _, mutator := range s.ServiceMutators {
		mutator(k8sSvc, newService)
	}

	s.mutex.Lock()
	defer s.mutex.Unlock()

	oldService, ok := s.services[svcID]
	if ok {
		if oldService.DeepEqual(newService) {
			return svcID
		}
		s.metrics.DelService(oldService)
	}

	s.metrics.AddService(newService)
	s.services[svcID] = newService

	// Check if the corresponding Endpoints resource is already available
	endpoints, serviceReady := s.correlateEndpoints(svcID)
	if serviceReady {
		s.emitEvent(ServiceEvent{
			Action:       UpdateService,
			ID:           svcID,
			Service:      newService,
			OldService:   oldService,
			Endpoints:    endpoints,
			OldEndpoints: endpoints,
			SWGDone:      swg.Add(),
		})
	}

	return svcID
}

func (s *ServiceCacheImpl) EnsureService(svcID ServiceID, swg *lock.StoppableWaitGroup) bool {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	if svc, found := s.services[svcID]; found {
		if endpoints, serviceReady := s.correlateEndpoints(svcID); serviceReady {
			s.emitEvent(ServiceEvent{
				Action:       UpdateService,
				ID:           svcID,
				Service:      svc,
				OldService:   svc,
				Endpoints:    endpoints,
				OldEndpoints: endpoints,
				SWGDone:      swg.Add(),
			})
			return true
		}
	}
	return false
}

// DeleteService parses a Kubernetes service and removes it from the
// ServiceCache
func (s *ServiceCacheImpl) DeleteService(k8sSvc *slim_corev1.Service, swg *lock.StoppableWaitGroup) {
	svcID := ParseServiceID(k8sSvc)

	s.mutex.Lock()
	defer s.mutex.Unlock()

	oldService, serviceOK := s.services[svcID]
	endpoints, _ := s.correlateEndpoints(svcID)
	delete(s.services, svcID)

	if serviceOK {
		s.metrics.DelService(oldService)
		s.emitEvent(ServiceEvent{
			Action:    DeleteService,
			ID:        svcID,
			Service:   oldService,
			Endpoints: endpoints,
			SWGDone:   swg.Add(),
		})
	}
}

// LocalServices returns the list of known services that are not marked as
// global (i.e., whose backends are all in the local cluster only).
func (s *ServiceCacheImpl) LocalServices() sets.Set[ServiceID] {
	ids := sets.New[ServiceID]()

	s.mutex.RLock()
	defer s.mutex.RUnlock()

	for id, svc := range s.services {
		if !svc.IncludeExternal {
			ids.Insert(id)
		}
	}

	return ids
}

// UpdateEndpoints parses a Kubernetes endpoints and adds or updates it in the
// ServiceCache. Returns the ServiceID unless the Kubernetes endpoints could not
// be parsed and a bool to indicate whether the endpoints was changed in the
// cache or not.
func (s *ServiceCacheImpl) UpdateEndpoints(newEndpoints *Endpoints, swg *lock.StoppableWaitGroup) (ServiceID, *Endpoints) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	esID := newEndpoints.EndpointSliceID

	var oldEPs *Endpoints
	eps, ok := s.endpoints[esID.ServiceID]
	if ok {
		oldEPs = eps.epSlices[esID.EndpointSliceName]
		if oldEPs.DeepEqual(newEndpoints) {
			return esID.ServiceID, newEndpoints
		}
	} else {
		eps = NewEndpointsSlices()
		s.endpoints[esID.ServiceID] = eps
	}

	eps.Upsert(esID.EndpointSliceName, newEndpoints)

	// Check if the corresponding Endpoints resource is already available
	svc, ok := s.services[esID.ServiceID]
	endpoints, serviceReady := s.correlateEndpoints(esID.ServiceID)
	if ok && serviceReady {
		s.emitEvent(ServiceEvent{
			Action:       UpdateService,
			ID:           esID.ServiceID,
			Service:      svc,
			Endpoints:    endpoints,
			OldEndpoints: oldEPs,
			SWGDone:      swg.Add(),
		})
	}

	return esID.ServiceID, endpoints
}

// DeleteEndpoints parses a Kubernetes endpoints and removes it from the
// ServiceCache
func (s *ServiceCacheImpl) DeleteEndpoints(svcID EndpointSliceID, swg *lock.StoppableWaitGroup) ServiceID {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	var oldEPs *Endpoints
	svc, serviceOK := s.services[svcID.ServiceID]
	eps, ok := s.endpoints[svcID.ServiceID]
	if ok {
		oldEPs = eps.epSlices[svcID.EndpointSliceName].DeepCopy() // copy for passing to ServiceEvent
		isEmpty := eps.Delete(svcID.EndpointSliceName)
		if isEmpty {
			delete(s.endpoints, svcID.ServiceID)
		}
	}
	endpoints, _ := s.correlateEndpoints(svcID.ServiceID)

	if serviceOK {
		event := ServiceEvent{
			Action:       UpdateService,
			ID:           svcID.ServiceID,
			Service:      svc,
			Endpoints:    endpoints,
			OldEndpoints: oldEPs,
			SWGDone:      swg.Add(),
		}

		s.emitEvent(event)
	}

	return svcID.ServiceID
}

// FrontendList is the list of all k8s service frontends
type FrontendList map[string]struct{}

// filterEndpoints filters local endpoints by using k8s service heuristics.
// For now it only implements the topology aware hints.
func (s *ServiceCacheImpl) filterEndpoints(localEndpoints *Endpoints, svc *Service) *Endpoints {
	if !s.config.EnableServiceTopology || svc == nil {
		return localEndpoints
	}

	if s.selfNodeZoneLabel == "" {
		// The node doesn't have the zone label set, so we cannot filter endpoints
		// by zone. Therefore, return all endpoints.
		return localEndpoints
	}

	if svc.ExtTrafficPolicy == loadbalancer.SVCTrafficPolicyLocal || svc.IntTrafficPolicy == loadbalancer.SVCTrafficPolicyLocal {
		// According to https://kubernetes.io/docs/concepts/services-networking/topology-aware-hints/#constraints:
		// """
		// Topology Aware Hints are not used when either externalTrafficPolicy or
		// internalTrafficPolicy is set to Local on a Service.
		// """
		return localEndpoints
	}

	filteredEndpoints := &Endpoints{Backends: map[cmtypes.AddrCluster]*Backend{}}

	for key, backend := range localEndpoints.Backends {
		if len(backend.HintsForZones) == 0 {
			return localEndpoints
		}

		if slices.Contains(backend.HintsForZones, s.selfNodeZoneLabel) {
			filteredEndpoints.Backends[key] = backend
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

// correlateEndpoints builds a combined Endpoints of the local endpoints and
// all external endpoints if the service is marked as a global service. Also
// returns a boolean that indicates whether the service is ready to be plumbed,
// this is true if:
// A local endpoints resource is present. Regardless whether the
//
//	endpoints resource contains actual backends or not.
//
// OR Remote endpoints exist which correlate to the service.
func (s *ServiceCacheImpl) correlateEndpoints(id ServiceID) (*Endpoints, bool) {
	endpoints := s.endpoints[id].GetEndpoints()
	svc, svcFound := s.services[id]

	hasLocalEndpoints := endpoints != nil
	if hasLocalEndpoints {
		endpoints = s.filterEndpoints(endpoints, svc)

		for _, e := range endpoints.Backends {
			// The endpoints returned by GetEndpoints are already deep copies,
			// hence we can mutate them in-place without problems.
			e.Preferred = svcFound && svc.IncludeExternal && svc.ServiceAffinity == annotation.ServiceAffinityLocal
		}
	} else {
		endpoints = newEndpoints()
	}

	var hasExternalEndpoints bool
	if svcFound && svc.IncludeExternal {
		externalEndpoints, ok := s.externalEndpoints[id]
		hasExternalEndpoints = ok && len(externalEndpoints.endpoints) > 0
		if hasExternalEndpoints {
			// remote cluster endpoints already contain all Endpoints from all
			// EndpointSlices so no need to search the endpoints of a particular
			// EndpointSlice.
			for clusterName, remoteClusterEndpoints := range externalEndpoints.endpoints {
				for ip, e := range remoteClusterEndpoints.Backends {
					if _, ok := endpoints.Backends[ip]; ok {
						s.logger.Warn(
							"Conflicting service backend IP",
							logfields.K8sSvcName, id.Name,
							logfields.K8sNamespace, id.Namespace,
							logfields.IPAddr, ip,
							logfields.ClusterName, clusterName,
						)
					} else {
						e.Preferred = svc.ServiceAffinity == annotation.ServiceAffinityRemote
						endpoints.Backends[ip] = e.DeepCopy()
					}
				}
			}
		}
	}

	// Report the service as ready if a local endpoints object exists or if
	// external endpoints have been identified
	return endpoints, hasLocalEndpoints || hasExternalEndpoints
}

// mergeExternalServiceOption is the type for the options to customize the behavior of external services merging.
type mergeExternalServiceOption int

const (
	// optClusterAware enables the cluster aware handling for external services merging.
	optClusterAware mergeExternalServiceOption = iota
)

// MergeExternalServiceUpdate merges a cluster service of a remote cluster into
// the local service cache. The service endpoints are stored as external endpoints
// and are correlated on demand with local services via correlateEndpoints().
func (s *ServiceCacheImpl) MergeExternalServiceUpdate(service *serviceStore.ClusterService, swg *lock.StoppableWaitGroup) {
	// Ignore updates of own cluster
	if service.Cluster == option.Config.ClusterName {
		return
	}

	s.mutex.Lock()
	defer s.mutex.Unlock()

	s.mergeServiceUpdateLocked(service, nil, swg)
}

func (s *ServiceCacheImpl) mergeServiceUpdateLocked(service *serviceStore.ClusterService,
	oldService *Service, swg *lock.StoppableWaitGroup, opts ...mergeExternalServiceOption) {

	id := ServiceID{Name: service.Name, Namespace: service.Namespace}
	if slices.Contains(opts, optClusterAware) {
		id.Cluster = service.Cluster
	}

	externalEndpoints, ok := s.externalEndpoints[id]
	if !ok {
		externalEndpoints = newExternalEndpoints()
		s.externalEndpoints[id] = externalEndpoints
	}

	oldEPs, _ := s.correlateEndpoints(id)

	// The cluster the service belongs to will match the current one when dealing with external
	// workloads (and in that case all endpoints shall be always present), and not match in the
	// cluster-mesh case (where remote endpoints shall be used only if it is shared).
	if service.Cluster != option.Config.ClusterName && !service.Shared {
		delete(externalEndpoints.endpoints, service.Cluster)
	} else {
		s.logger.Debug(
			"Updating backends",
			logfields.ServiceName, service,
			logfields.Backends, service.Backends,
		)

		backends := map[cmtypes.AddrCluster]*Backend{}
		for ipString, portConfig := range service.Backends {
			addr, err := cmtypes.ParseAddrCluster(ipString)
			if err != nil {
				s.logger.Error(
					"Skipping service backend due to invalid IP address",
					logfields.ServiceName, service,
					logfields.IPAddr, ipString,
				)
				continue
			}

			backends[addr] = &Backend{Ports: portConfig}
		}
		externalEndpoints.endpoints[service.Cluster] = &Endpoints{
			Backends: backends,
		}
	}

	svc, ok := s.services[id]

	endpoints, serviceReady := s.correlateEndpoints(id)

	// Only send event notification if service is ready.
	if ok && serviceReady {
		s.emitEvent(ServiceEvent{
			Action:       UpdateService,
			ID:           id,
			Service:      svc,
			OldService:   oldService,
			Endpoints:    endpoints,
			OldEndpoints: oldEPs,
			SWGDone:      swg.Add(),
		})
	}
}

// MergeExternalServiceDelete merges the deletion of a cluster service in a
// remote cluster into the local service cache. The service endpoints are
// stored as external endpoints and are correlated on demand with local
// services via correlateEndpoints().
func (s *ServiceCacheImpl) MergeExternalServiceDelete(service *serviceStore.ClusterService, swg *lock.StoppableWaitGroup) {
	// Ignore updates of own cluster
	if service.Cluster == option.Config.ClusterName {
		return
	}

	s.mutex.Lock()
	defer s.mutex.Unlock()

	id := ServiceID{Cluster: service.Cluster, Name: service.Name, Namespace: service.Namespace}
	var opts []mergeExternalServiceOption
	if _, clusterAware := s.services[id]; clusterAware {
		opts = append(opts, optClusterAware)
	}

	s.mergeExternalServiceDeleteLocked(service, swg, opts...)
}

func (s *ServiceCacheImpl) mergeExternalServiceDeleteLocked(service *serviceStore.ClusterService, swg *lock.StoppableWaitGroup, opts ...mergeExternalServiceOption) {
	id := ServiceID{Name: service.Name, Namespace: service.Namespace}
	if slices.Contains(opts, optClusterAware) {
		id.Cluster = service.Cluster
	}

	externalEndpoints, ok := s.externalEndpoints[id]
	if ok {
		s.logger.Debug(
			"Deleting external endpoints",
			logfields.ServiceName, service,
		)

		oldEPs, _ := s.correlateEndpoints(id)

		delete(externalEndpoints.endpoints, service.Cluster)
		if len(externalEndpoints.endpoints) == 0 {
			delete(s.externalEndpoints, id)
		}

		svc, ok := s.services[id]

		endpoints, serviceReady := s.correlateEndpoints(id)

		// Only send event notification if service is shared.
		if ok && svc.Shared {
			event := ServiceEvent{
				Action:       UpdateService,
				ID:           id,
				Service:      svc,
				Endpoints:    endpoints,
				OldEndpoints: oldEPs,
				SWGDone:      swg.Add(),
			}

			if !serviceReady {
				delete(s.services, id)
				event.Action = DeleteService
			}

			s.emitEvent(event)
		}
	} else {
		s.logger.Debug(
			"Received delete event for non-existing endpoints",
			logfields.ServiceName, service,
		)
	}
}

// DebugStatus implements debug.StatusObject to provide debug status collection
// ability
func (s *ServiceCacheImpl) DebugStatus() string {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	// Create a temporary struct excluding the fields we want to ignore.
	dumpable := struct {
		Config            ServiceCacheConfig
		Services          map[ServiceID]*Service
		Endpoints         map[ServiceID]*EndpointSlices
		ExternalEndpoints map[ServiceID]externalEndpoints
		SelfNodeZoneLabel string
	}{
		Config:            s.config,
		Services:          s.services,
		Endpoints:         s.endpoints,
		ExternalEndpoints: s.externalEndpoints,
		SelfNodeZoneLabel: s.selfNodeZoneLabel,
	}

	// Dump the temporary structure.
	return spew.Sdump(dumpable)
}

func (s *ServiceCacheImpl) updateSelfNodeLabels(labels map[string]string) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	zone := labels[core_v1.LabelTopologyZone]

	if s.selfNodeZoneLabel == zone {
		return
	}

	s.selfNodeZoneLabel = zone

	for id, svc := range s.services {
		if !svc.TopologyAware {
			continue
		}

		if endpoints, ready := s.correlateEndpoints(id); ready {
			swg := lock.NewStoppableWaitGroup()
			s.emitEvent(ServiceEvent{
				Action:       UpdateService,
				ID:           id,
				Service:      svc,
				OldService:   svc,
				Endpoints:    endpoints,
				OldEndpoints: endpoints,
				SWGDone:      swg.Add(),
			})
		}
	}
}

type SVCMetrics interface {
	AddService(svc *Service)
	DelService(svc *Service)
}

type svcMetricsNoop struct {
}

func (s svcMetricsNoop) AddService(svc *Service) {
}

func (s svcMetricsNoop) DelService(svc *Service) {
}

func NewSVCMetricsNoop() SVCMetrics {
	return &svcMetricsNoop{}
}
