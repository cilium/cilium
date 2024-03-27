package k8s

import (
	"context"
	"net"

	"github.com/spf13/pflag"
	"k8s.io/apimachinery/pkg/util/sets"

	"github.com/cilium/stream"

	"github.com/cilium/cilium/daemon/tables"
	"github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/hive/job"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/lock"
	serviceStore "github.com/cilium/cilium/pkg/service/store"
	"github.com/cilium/cilium/pkg/statedb"
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

type ServiceCache struct {
	params serviceCacheParams

	Events     <-chan ServiceEvent
	eventsSink chan<- ServiceEvent
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

// TODO fix uses of this
func NewServiceCache(nodeAddressing types.NodeAddressing) *ServiceCache {
	return &ServiceCache{}
}

type serviceCacheParams struct {
	cell.In

	DB *statedb.DB

	ServiceTable statedb.Table[*tables.Service]
	BackendTable statedb.Table[*tables.Backend]
	Lifecycle    cell.Lifecycle
	Jobs         job.Registry
	Scope        cell.Scope
}

func newServiceCache(p serviceCacheParams) *ServiceCache {
	sc := &ServiceCache{
		params: p,
	}
	g := p.Jobs.NewGroup(p.Scope)
	g.Add(job.OneShot("event-loop", sc.eventLoop))
	p.Lifecycle.Append(g)
	return sc
}

func toEndpoints(backends []*tables.Backend) *Endpoints {
	return &Endpoints{}
}

func (s *ServiceCache) toEvent(ev statedb.Event[*tables.Service], oldEv *ServiceEvent) ServiceEvent {
	svc := ev.Object
	txn := s.params.DB.ReadTxn()
	iter, _ := s.params.BackendTable.Get(txn, tables.BackendServiceIndex.Query(svc.Name))
	eps := toEndpoints(statedb.Collect(iter))

	id := ServiceID{
		Cluster:   svc.Name.Cluster,
		Name:      svc.Name.Name,
		Namespace: svc.Name.Namespace,
	}

	act := UpdateService
	if ev.Deleted {
		act = DeleteService
	}

	// Note that here we don't emit one big ServiceEvent that has all the different
	// types in it (NodePort, ClusterIP, etc.), but rather we emit events for each
	// of the types. These anyway get expanded in datapathSVCs etc. so this is fine.

	var svc2 Service
	svc2.Type = svc.Type
	svc2.Labels = svc.Labels.K8sStringMap()
	svc2.IntTrafficPolicy = svc.IntPolicy
	svc2.ExtTrafficPolicy = svc.ExtPolicy

	switch svc.Type {
	case loadbalancer.SVCTypeNone:
	case loadbalancer.SVCTypeHostPort:
	case loadbalancer.SVCTypeClusterIP:
		svc2.FrontendIPs = []net.IP{svc.L3n4Addr.AddrCluster.AsNetIP()}
		svc2.Ports = map[loadbalancer.FEPortName]*loadbalancer.L4Addr{}
		// FIXME carry port name
		svc2.Ports["fixme"] = &svc.L3n4Addr.L4Addr

	case loadbalancer.SVCTypeNodePort:
		// FIXME query NodeAddress for proper frontend IP
		svc2.NodePorts = map[loadbalancer.FEPortName]NodePortToFrontend{}
		svc2.NodePorts["fixme"] = NodePortToFrontend{
			"fixme": &loadbalancer.L3n4AddrID{L3n4Addr: svc.L3n4Addr},
		}
	case loadbalancer.SVCTypeExternalIPs:
	case loadbalancer.SVCTypeLoadBalancer:
	case loadbalancer.SVCTypeLocalRedirect:
	}

	// TODO: Shared, IncludeExternal should be part of tables.Service?

	/*
		svc2 := &Service{
			FrontendIPs:               []net.IP{},
			IsHeadless:                false,
			IncludeExternal:           false,
			Shared:                    false,
			ServiceAffinity:           "",
			ExtTrafficPolicy:          "",
			IntTrafficPolicy:          "",
			HealthCheckNodePort:       0,
			Ports:                     map[loadbalancer.FEPortName]*loadbalancer.L4Addr{},
			NodePorts:                 map[loadbalancer.FEPortName]NodePortToFrontend{},
			K8sExternalIPs:            map[string]net.IP{},
			LoadBalancerIPs:           map[string]net.IP{},
			LoadBalancerSourceRanges:  map[string]*cidr.CIDR{},
			Labels:                    map[string]string{},
			Selector:                  map[string]string{},
			SessionAffinity:           false,
			SessionAffinityTimeoutSec: 0,
			Type:                      "",
			TopologyAware:             false,
		}*/

	return ServiceEvent{
		Action:       act,
		ID:           id,
		Service:      &svc2,
		OldService:   oldEv.Service,
		Endpoints:    eps,
		OldEndpoints: oldEv.Endpoints,
		SWG:          lock.NewStoppableWaitGroup(),
	}
}

func (s *ServiceCache) eventLoop(ctx context.Context, health cell.HealthReporter) error {
	src := stream.ToChannel(
		ctx,
		statedb.Observable(s.params.DB, s.params.ServiceTable),
	)

	oldEvents := map[loadbalancer.ServiceName]*ServiceEvent{}

	for {
		select {
		case <-ctx.Done():
			return nil

		case ev := <-src:
			sev := s.toEvent(ev, oldEvents[ev.Object.Name])
			oldEvents[ev.Object.Name] = &sev
			s.eventsSink <- sev
		}
	}
}

func (s *ServiceCache) UpdateService(k8sSvc *slim_corev1.Service, swg *lock.StoppableWaitGroup) ServiceID {
	return ServiceID{}
}

func (s *ServiceCache) UpdateEndpoints(newEndpoints *Endpoints, swg *lock.StoppableWaitGroup) (ServiceID, *Endpoints) {
	return ServiceID{}, nil
}

func (s *ServiceCache) DeleteService(k8sSvc *slim_corev1.Service, swg *lock.StoppableWaitGroup) {
}

func (s *ServiceCache) DeleteEndpoints(svcID EndpointSliceID, swg *lock.StoppableWaitGroup) ServiceID {
	return ServiceID{}
}

func (s *ServiceCache) EnsureService(svcID ServiceID, swg *lock.StoppableWaitGroup) bool {
	return true
}

func (s *ServiceCache) GetServiceIP(svcID ServiceID) *loadbalancer.L3n4Addr {
	return nil
}

func (s *ServiceCache) MergeExternalServiceUpdate(service *serviceStore.ClusterService, swg *lock.StoppableWaitGroup) {
}

func (s *ServiceCache) MergeExternalServiceDelete(service *serviceStore.ClusterService, swg *lock.StoppableWaitGroup) {
}

func (s *ServiceCache) MergeClusterServiceUpdate(service *serviceStore.ClusterService, swg *lock.StoppableWaitGroup) {
}

func (s *ServiceCache) MergeClusterServiceDelete(service *serviceStore.ClusterService, swg *lock.StoppableWaitGroup) {
}

func (s *ServiceCache) GetServiceAddrsWithType(svcID ServiceID,
	svcType loadbalancer.SVCType) (map[loadbalancer.FEPortName][]*loadbalancer.L3n4Addr, int) {
	return nil, 0
}

func (s *ServiceCache) GetServiceFrontendIP(svcID ServiceID, svcType loadbalancer.SVCType) net.IP {
	return nil
}

func (s *ServiceCache) GetEndpointsOfService(svcID ServiceID) *Endpoints {
	return nil
}

func (s *ServiceCache) LocalServices() sets.Set[ServiceID] {
	return nil
}

type FrontendList map[string]struct{}

func (s *ServiceCache) UniqueServiceFrontends() FrontendList {
	return nil
}

func (s *ServiceCache) GetNodeAddressing() types.NodeAddressing {
	return nil
}

func (s *ServiceCache) Notifications() stream.Observable[ServiceNotification] {
	return nil
}

func (s *ServiceCache) ForEachService(yield func(svcID ServiceID, svc *Service, eps *Endpoints) bool) {
}

func (s *ServiceCache) DebugStatus() string {
	return ""
}
