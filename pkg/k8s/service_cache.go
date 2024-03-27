package k8s

import (
	"net"

	"github.com/spf13/pflag"
	"k8s.io/apimachinery/pkg/util/sets"

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
}

// TODO fix uses of this
func NewServiceCache(nodeAddressing types.NodeAddressing) *ServiceCache {
	return &ServiceCache{}
}

type serviceCacheParams struct {
	cell.In

	DB *statedb.DB

	NodeAddressing types.NodeAddressing
	//ServiceTable   statedb.Table[*tables.Service]
	//BackendTable   statedb.Table[*tables.Backend]
	Lifecycle cell.Lifecycle
	Jobs      job.Registry
	Scope     cell.Scope
}

func newServiceCache(p serviceCacheParams) *ServiceCache {
	sc := &ServiceCache{
		params: p,
	}
	return sc
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
	return s.params.NodeAddressing
}

func (s *ServiceCache) ForEachService(yield func(svcID ServiceID, svc *Service, eps *Endpoints) bool) {
}

func (s *ServiceCache) DebugStatus() string {
	return ""
}
