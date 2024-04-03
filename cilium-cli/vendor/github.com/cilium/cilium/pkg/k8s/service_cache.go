// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package k8s

import (
	"context"
	"net"
	"slices"
	"sync"

	"github.com/cilium/stream"
	"github.com/davecgh/go-spew/spew"
	"github.com/sirupsen/logrus"
	"github.com/spf13/pflag"
	core_v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/sets"

	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/ip"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/option"
	serviceStore "github.com/cilium/cilium/pkg/service/store"
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

	// SWG provides a mechanism to detect if a service was synchronized with
	// the datapath.
	SWG *lock.StoppableWaitGroup
}

// ServiceNotification is a slimmed down version of a ServiceEvent. In particular
// notifications are optional and thus do not contain a wait group to allow
// producers to wait for the notification to be consumed.
type ServiceNotification struct {
	Action       CacheAction
	ID           ServiceID
	Service      *Service
	OldService   *Service
	Endpoints    *Endpoints
	OldEndpoints *Endpoints
}

// ServiceCache is a list of services correlated with the matching endpoints.
// The Events member will receive events as services.
type ServiceCache struct {
	config ServiceCacheConfig

	// Events may only be read by single consumer. The consumer must acknowledge
	// every event by calling Done() on the ServiceEvent.SWG.
	Events     <-chan ServiceEvent
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

	nodeAddressing types.NodeAddressing

	selfNodeZoneLabel string

	ServiceMutators []func(svc *slim_corev1.Service, svcInfo *Service)
}

// NewServiceCache returns a new ServiceCache
func NewServiceCache(nodeAddressing types.NodeAddressing) *ServiceCache {
	events := make(chan ServiceEvent, option.Config.K8sServiceCacheSize)
	notifications, emitNotifications, completeNotifications := stream.Multicast[ServiceNotification]()

	return &ServiceCache{
		services:              map[ServiceID]*Service{},
		endpoints:             map[ServiceID]*EndpointSlices{},
		externalEndpoints:     map[ServiceID]externalEndpoints{},
		Events:                events,
		sendEvents:            events,
		notifications:         notifications,
		emitNotifications:     emitNotifications,
		completeNotifications: completeNotifications,
		nodeAddressing:        nodeAddressing,
	}
}

func newServiceCache(lc cell.Lifecycle, nodeAddressing types.NodeAddressing, cfg ServiceCacheConfig, lns *node.LocalNodeStore) *ServiceCache {
	sc := NewServiceCache(nodeAddressing)
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

func (s *ServiceCache) emitEvent(event ServiceEvent) {
	s.sendEvents <- event
	s.emitNotifications(ServiceNotification{
		Action:       event.Action,
		ID:           event.ID,
		Service:      event.Service,
		OldService:   event.OldService,
		Endpoints:    event.Endpoints,
		OldEndpoints: event.OldEndpoints,
	})
}

// Notifications allow multiple subscribers to observe changes to services and
// endpoints.
// Subscribers must register as soon as the service cache is created to ensure
// no notifications are missed, as notifications which happen before a consumer
// is subscribed will be lost.
func (s *ServiceCache) Notifications() stream.Observable[ServiceNotification] {
	return s.notifications
}

// GetServiceIP returns a random L3n4Addr that is backing the given Service ID.
// The returned IP is with external scope since its string representation might
// be used for net Dialer.
func (s *ServiceCache) GetServiceIP(svcID ServiceID) *loadbalancer.L3n4Addr {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	svc := s.services[svcID]
	if svc == nil || len(svc.FrontendIPs) == 0 || len(svc.Ports) == 0 {
		return nil
	}

	feIP := ip.GetIPFromListByFamily(svc.FrontendIPs, option.Config.EnableIPv4)
	if feIP == nil {
		return nil
	}

	for _, port := range svc.Ports {
		return loadbalancer.NewL3n4Addr(port.Protocol, cmtypes.MustAddrClusterFromIP(feIP), port.Port,
			loadbalancer.ScopeExternal)
	}
	return nil
}

// GetServiceFrontendIP returns the frontend IP (aka clusterIP) for the given service with type.
func (s *ServiceCache) GetServiceFrontendIP(svcID ServiceID, svcType loadbalancer.SVCType) net.IP {
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
func (s *ServiceCache) GetServiceAddrsWithType(svcID ServiceID,
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

// GetEndpointsOfService returns all the endpoints that correlate with a
// service given a ServiceID.
func (s *ServiceCache) GetEndpointsOfService(svcID ServiceID) *Endpoints {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	eps, ok := s.endpoints[svcID]
	if !ok {
		return nil
	}
	return eps.GetEndpoints()
}

// GetNodeAddressing returns the registered node addresses to this service cache.
func (s *ServiceCache) GetNodeAddressing() types.NodeAddressing {
	return s.nodeAddressing
}

// ForEachService runs the yield callback for each service and its endpoints.
// If yield returns false, the iteration is terminated early.
// Services are iterated in random order.
// The ServiceCache is read-locked during this function call. The passed in
// Service and Endpoints references are read-only.
func (s *ServiceCache) ForEachService(yield func(svcID ServiceID, svc *Service, eps *Endpoints) bool) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	for svcID, ep := range s.endpoints {
		svc, ok := s.services[svcID]
		if !ok {
			continue
		}
		eps := ep.GetEndpoints()
		if !yield(svcID, svc, eps) {
			return
		}
	}
}

// UpdateService parses a Kubernetes service and adds or updates it in the
// ServiceCache. Returns the ServiceID unless the Kubernetes service could not
// be parsed and a bool to indicate whether the service was changed in the
// cache or not.
func (s *ServiceCache) UpdateService(k8sSvc *slim_corev1.Service, swg *lock.StoppableWaitGroup) ServiceID {
	svcID, newService := ParseService(k8sSvc, s.nodeAddressing)
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
	}

	s.services[svcID] = newService

	// Check if the corresponding Endpoints resource is already available
	endpoints, serviceReady := s.correlateEndpoints(svcID)
	if serviceReady {
		swg.Add()
		s.emitEvent(ServiceEvent{
			Action:       UpdateService,
			ID:           svcID,
			Service:      newService,
			OldService:   oldService,
			Endpoints:    endpoints,
			OldEndpoints: endpoints,
			SWG:          swg,
		})
	}

	return svcID
}

func (s *ServiceCache) EnsureService(svcID ServiceID, swg *lock.StoppableWaitGroup) bool {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	if svc, found := s.services[svcID]; found {
		if endpoints, serviceReady := s.correlateEndpoints(svcID); serviceReady {
			swg.Add()
			s.emitEvent(ServiceEvent{
				Action:       UpdateService,
				ID:           svcID,
				Service:      svc,
				OldService:   svc,
				Endpoints:    endpoints,
				OldEndpoints: endpoints,
				SWG:          swg,
			})
			return true
		}
	}
	return false
}

// DeleteService parses a Kubernetes service and removes it from the
// ServiceCache
func (s *ServiceCache) DeleteService(k8sSvc *slim_corev1.Service, swg *lock.StoppableWaitGroup) {
	svcID := ParseServiceID(k8sSvc)

	s.mutex.Lock()
	defer s.mutex.Unlock()

	oldService, serviceOK := s.services[svcID]
	endpoints, _ := s.correlateEndpoints(svcID)
	delete(s.services, svcID)

	if serviceOK {
		swg.Add()
		s.emitEvent(ServiceEvent{
			Action:    DeleteService,
			ID:        svcID,
			Service:   oldService,
			Endpoints: endpoints,
			SWG:       swg,
		})
	}
}

// LocalServices returns the list of known services that are not marked as
// global (i.e., whose backends are all in the local cluster only).
func (s *ServiceCache) LocalServices() sets.Set[ServiceID] {
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
func (s *ServiceCache) UpdateEndpoints(newEndpoints *Endpoints, swg *lock.StoppableWaitGroup) (ServiceID, *Endpoints) {
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
		eps = newEndpointsSlices()
		s.endpoints[esID.ServiceID] = eps
	}

	eps.Upsert(esID.EndpointSliceName, newEndpoints)

	// Check if the corresponding Endpoints resource is already available
	svc, ok := s.services[esID.ServiceID]
	endpoints, serviceReady := s.correlateEndpoints(esID.ServiceID)
	if ok && serviceReady {
		swg.Add()
		s.emitEvent(ServiceEvent{
			Action:       UpdateService,
			ID:           esID.ServiceID,
			Service:      svc,
			Endpoints:    endpoints,
			OldEndpoints: oldEPs,
			SWG:          swg,
		})
	}

	return esID.ServiceID, endpoints
}

// DeleteEndpoints parses a Kubernetes endpoints and removes it from the
// ServiceCache
func (s *ServiceCache) DeleteEndpoints(svcID EndpointSliceID, swg *lock.StoppableWaitGroup) ServiceID {
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
		swg.Add()
		event := ServiceEvent{
			Action:       UpdateService,
			ID:           svcID.ServiceID,
			Service:      svc,
			Endpoints:    endpoints,
			OldEndpoints: oldEPs,
			SWG:          swg,
		}

		s.emitEvent(event)
	}

	return svcID.ServiceID
}

// FrontendList is the list of all k8s service frontends
type FrontendList map[string]struct{}

// LooseMatch returns true if the provided frontend is found in the
// FrontendList. If the frontend has a protocol value set, it only matches a
// k8s service with a matching protocol. If no protocol is set, any k8s service
// matching frontend IP and port is considered a match, regardless of protocol.
func (l FrontendList) LooseMatch(frontend loadbalancer.L3n4Addr) (exists bool) {
	switch frontend.Protocol {
	case loadbalancer.NONE:
		for _, protocol := range loadbalancer.AllProtocols {
			frontend.Protocol = protocol
			_, exists = l[frontend.StringWithProtocol()]
			if exists {
				return
			}
		}

	// If the protocol is set, perform an exact match
	default:
		_, exists = l[frontend.StringWithProtocol()]
	}
	return
}

// UniqueServiceFrontends returns all externally scoped services known to
// the service cache as a map, indexed by the string representation of a
// loadbalancer.L3n4Addr. This helper is only used in unit tests.
func (s *ServiceCache) UniqueServiceFrontends() FrontendList {
	uniqueFrontends := FrontendList{}

	s.mutex.RLock()
	defer s.mutex.RUnlock()

	for _, svc := range s.services {
		for _, feIP := range svc.FrontendIPs {
			for _, p := range svc.Ports {
				address := loadbalancer.L3n4Addr{
					AddrCluster: cmtypes.MustAddrClusterFromIP(feIP),
					L4Addr:      *p,
					Scope:       loadbalancer.ScopeExternal,
				}
				uniqueFrontends[address.StringWithProtocol()] = struct{}{}
			}
		}

		for _, nodePortFEs := range svc.NodePorts {
			for _, fe := range nodePortFEs {
				if fe.Scope == loadbalancer.ScopeExternal {
					uniqueFrontends[fe.StringWithProtocol()] = struct{}{}
				}
			}
		}
	}

	return uniqueFrontends
}

// filterEndpoints filters local endpoints by using k8s service heuristics.
// For now it only implements the topology aware hints.
func (s *ServiceCache) filterEndpoints(localEndpoints *Endpoints, svc *Service) *Endpoints {
	if !s.config.EnableServiceTopology || svc == nil || !svc.TopologyAware {
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

		for _, hint := range backend.HintsForZones {
			if hint == s.selfNodeZoneLabel {
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

// correlateEndpoints builds a combined Endpoints of the local endpoints and
// all external endpoints if the service is marked as a global service. Also
// returns a boolean that indicates whether the service is ready to be plumbed,
// this is true if:
// A local endpoints resource is present. Regardless whether the
//
//	endpoints resource contains actual backends or not.
//
// OR Remote endpoints exist which correlate to the service.
func (s *ServiceCache) correlateEndpoints(id ServiceID) (*Endpoints, bool) {
	endpoints := newEndpoints()

	localEndpoints := s.endpoints[id].GetEndpoints()
	svc, svcFound := s.services[id]

	hasLocalEndpoints := localEndpoints != nil
	if hasLocalEndpoints {
		localEndpoints = s.filterEndpoints(localEndpoints, svc)

		for ip, e := range localEndpoints.Backends {
			e.Preferred = svcFound && svc.IncludeExternal && svc.ServiceAffinity == serviceAffinityLocal
			endpoints.Backends[ip] = e.DeepCopy()
		}
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
						log.WithFields(logrus.Fields{
							logfields.K8sSvcName:   id.Name,
							logfields.K8sNamespace: id.Namespace,
							logfields.IPAddr:       ip,
							"cluster":              clusterName,
						}).Warning("Conflicting service backend IP")
					} else {
						e.Preferred = svc.ServiceAffinity == serviceAffinityRemote
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
func (s *ServiceCache) MergeExternalServiceUpdate(service *serviceStore.ClusterService, swg *lock.StoppableWaitGroup) {
	// Ignore updates of own cluster
	if service.Cluster == option.Config.ClusterName {
		return
	}

	s.mutex.Lock()
	defer s.mutex.Unlock()

	s.mergeServiceUpdateLocked(service, nil, swg)
}

func (s *ServiceCache) mergeServiceUpdateLocked(service *serviceStore.ClusterService,
	oldService *Service, swg *lock.StoppableWaitGroup, opts ...mergeExternalServiceOption) {
	scopedLog := log.WithFields(logrus.Fields{logfields.ServiceName: service.String()})

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
		scopedLog.Debugf("Updating backends to %+v", service.Backends)
		backends := map[cmtypes.AddrCluster]*Backend{}
		for ipString, portConfig := range service.Backends {
			addr, err := cmtypes.ParseAddrCluster(ipString)
			if err != nil {
				scopedLog.WithField(logfields.IPAddr, ipString).
					Error("Skipping service backend due to invalid IP address")
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
		swg.Add()
		s.emitEvent(ServiceEvent{
			Action:       UpdateService,
			ID:           id,
			Service:      svc,
			OldService:   oldService,
			Endpoints:    endpoints,
			OldEndpoints: oldEPs,
			SWG:          swg,
		})
	}
}

// MergeExternalServiceDelete merges the deletion of a cluster service in a
// remote cluster into the local service cache. The service endpoints are
// stored as external endpoints and are correlated on demand with local
// services via correlateEndpoints().
func (s *ServiceCache) MergeExternalServiceDelete(service *serviceStore.ClusterService, swg *lock.StoppableWaitGroup) {
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

func (s *ServiceCache) mergeExternalServiceDeleteLocked(service *serviceStore.ClusterService, swg *lock.StoppableWaitGroup, opts ...mergeExternalServiceOption) {
	scopedLog := log.WithFields(logrus.Fields{logfields.ServiceName: service.String()})

	id := ServiceID{Name: service.Name, Namespace: service.Namespace}
	if slices.Contains(opts, optClusterAware) {
		id.Cluster = service.Cluster
	}

	externalEndpoints, ok := s.externalEndpoints[id]
	if ok {
		scopedLog.Debug("Deleting external endpoints")

		oldEPs, _ := s.correlateEndpoints(id)

		delete(externalEndpoints.endpoints, service.Cluster)
		if len(externalEndpoints.endpoints) == 0 {
			delete(s.externalEndpoints, id)
		}

		svc, ok := s.services[id]

		endpoints, serviceReady := s.correlateEndpoints(id)

		// Only send event notification if service is shared.
		if ok && svc.Shared {
			swg.Add()
			event := ServiceEvent{
				Action:       UpdateService,
				ID:           id,
				Service:      svc,
				Endpoints:    endpoints,
				OldEndpoints: oldEPs,
				SWG:          swg,
			}

			if !serviceReady {
				delete(s.services, id)
				event.Action = DeleteService
			}

			s.emitEvent(event)
		}
	} else {
		scopedLog.Debug("Received delete event for non-existing endpoints")
	}
}

// MergeClusterServiceUpdate merges a cluster service of a local cluster into
// the local service cache. The service endpoints are stored as external endpoints
// and are correlated on demand with local services via correlateEndpoints().
// Local service is created and/or updated if needed.
func (s *ServiceCache) MergeClusterServiceUpdate(service *serviceStore.ClusterService, swg *lock.StoppableWaitGroup) {
	scopedLog := log.WithFields(logrus.Fields{logfields.ServiceName: service.String()})
	id := ServiceID{Name: service.Name, Namespace: service.Namespace}

	s.mutex.Lock()
	defer s.mutex.Unlock()

	var oldService *Service
	svc, ok := s.services[id]
	if !ok || !svc.EqualsClusterService(service) {
		oldService = svc
		svc = ParseClusterService(service)
		s.services[id] = svc
		scopedLog.Debugf("Added new service %v", svc)
	}
	s.mergeServiceUpdateLocked(service, oldService, swg)
}

// MergeClusterServiceDelete merges the deletion of a cluster service in a
// remote cluster into the local service cache, deleting the local service.
func (s *ServiceCache) MergeClusterServiceDelete(service *serviceStore.ClusterService, swg *lock.StoppableWaitGroup) {
	scopedLog := log.WithFields(logrus.Fields{logfields.ServiceName: service.String()})
	id := ServiceID{Name: service.Name, Namespace: service.Namespace}

	s.mutex.Lock()
	defer s.mutex.Unlock()

	externalEndpoints, ok := s.externalEndpoints[id]
	if ok {
		scopedLog.Debug("Deleting cluster endpoints")
		delete(externalEndpoints.endpoints, service.Cluster)
		if len(externalEndpoints.endpoints) == 0 {
			delete(s.externalEndpoints, id)
		}
	}

	svc, ok := s.services[id]
	endpoints, _ := s.correlateEndpoints(id)
	delete(s.services, id)

	if ok {
		swg.Add()
		s.emitEvent(ServiceEvent{
			Action:    DeleteService,
			ID:        id,
			Service:   svc,
			Endpoints: endpoints,
			SWG:       swg,
		})
	}
}

// DebugStatus implements debug.StatusObject to provide debug status collection
// ability
func (s *ServiceCache) DebugStatus() string {
	s.mutex.RLock()
	str := spew.Sdump(s)
	s.mutex.RUnlock()
	return str
}

func (s *ServiceCache) updateSelfNodeLabels(labels map[string]string) {
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
			swg.Add()
			s.emitEvent(ServiceEvent{
				Action:       UpdateService,
				ID:           id,
				Service:      svc,
				OldService:   svc,
				Endpoints:    endpoints,
				OldEndpoints: endpoints,
				SWG:          swg,
			})
		}
	}
}
