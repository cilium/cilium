package k8s

import (
	"net"

	"github.com/spf13/pflag"
	"k8s.io/apimachinery/pkg/util/sets"

	"github.com/cilium/stream"

	"github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/hive/cell"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/lock"
	serviceStore "github.com/cilium/cilium/pkg/service/store"
)

// ServiceCacheCell initializes the service cache holds the list of known services
// correlated with the matching endpoints
var ServiceCacheCell = cell.Module(
	"service-cache",
	"Service Cache",

	cell.Config(ServiceCacheConfig{}),
	cell.Provide(NewServiceCache),
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
	Events <-chan ServiceEvent
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

func NewServiceCache(nodeAddressing types.NodeAddressing) *ServiceCache {
	return &ServiceCache{}
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
