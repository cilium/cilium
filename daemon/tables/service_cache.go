package tables

import (
	"net"

	"github.com/spf13/pflag"
	"k8s.io/apimachinery/pkg/util/sets"

	"github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/hive/job"
	"github.com/cilium/cilium/pkg/k8s"
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
	// FIXME: Where/how do we implement this? Since the node zone labels can change,
	// we do need to hold on to all the backends. One option would be to have "Filtered"
	// field in the backend that is set if the backend is filtered due to zone labels not
	// matching. This can be done on-the-fly when upserting backends and we can have a controller
	// that updates the backends if zone labels for the node changes (needs synchronization)
	EnableServiceTopology bool
}

// Flags implements the cell.Flagger interface.
func (def ServiceCacheConfig) Flags(flags *pflag.FlagSet) {
	flags.Bool("enable-service-topology", def.EnableServiceTopology, "Enable support for service topology aware hints")
}

type ServiceCache struct {
	params serviceCacheParams
}

type serviceCacheParams struct {
	cell.In

	DB *statedb.DB

	NodeAddressing types.NodeAddressing
	ServiceTable   statedb.Table[*Service]
	BackendTable   statedb.Table[*Backend]
	Lifecycle      cell.Lifecycle
	Jobs           job.Registry
	Scope          cell.Scope
}

func newServiceCache(p serviceCacheParams) k8s.ServiceCache {
	sc := &ServiceCache{
		params: p,
	}
	return sc
}

func (s *ServiceCache) EnsureService(svcID k8s.ServiceID, swg *lock.StoppableWaitGroup) bool {
	// TODO: used by redirect manager. Unclear how to implement. Maybe no-op upsert of
	// matching services? Or just rewrite redirect manager.
	return true
}

func (s *ServiceCache) GetServiceIP(svcID k8s.ServiceID) *loadbalancer.L3n4Addr {
	// TODO: used by service dialer
	return nil
}

func (s *ServiceCache) MergeExternalServiceUpdate(service *serviceStore.ClusterService, swg *lock.StoppableWaitGroup) {
	// TODO: used by clustermesh
}

func (s *ServiceCache) MergeExternalServiceDelete(service *serviceStore.ClusterService, swg *lock.StoppableWaitGroup) {
	// TODO: used by clustermesh
}

func (s *ServiceCache) MergeClusterServiceUpdate(service *serviceStore.ClusterService, swg *lock.StoppableWaitGroup) {
	// TODO: used by clustermesh
}

func (s *ServiceCache) MergeClusterServiceDelete(service *serviceStore.ClusterService, swg *lock.StoppableWaitGroup) {
	// TODO: used by clustermesh
}

func (s *ServiceCache) GetServiceAddrsWithType(svcID k8s.ServiceID,
	svcType loadbalancer.SVCType) (map[loadbalancer.FEPortName][]*loadbalancer.L3n4Addr, int) {
	// TODO: used by redirect manager
	return nil, 0
}

func (s *ServiceCache) GetServiceFrontendIP(svcID k8s.ServiceID, svcType loadbalancer.SVCType) net.IP {
	// TODO: used by redirect manager
	return nil
}

func (s *ServiceCache) GetEndpointsOfService(svcID k8s.ServiceID) *k8s.Endpoints {
	// TODO: used by BGP
	return nil
}

func (s *ServiceCache) LocalServices() sets.Set[k8s.ServiceID] {
	// TODO: used by lbmap post-restoration cleanup. Need to look into how this should work.
	return nil
}

func (s *ServiceCache) GetNodeAddressing() types.NodeAddressing {
	// TODO: used by pod watcher (consider rewriting the pod watcher)
	return s.params.NodeAddressing
}

func (s *ServiceCache) ForEachService(yield func(svcID k8s.ServiceID, svc *k8s.Service, eps *k8s.Endpoints) bool) {
	// TODO: used by policy
	// Consider a slightly different API for this to avoid having to construct *k8s.Service from
	// tables.Service. Or better yet, just rewrite pkg/policy/k8s to work against the tables.
}

func (s *ServiceCache) DebugStatus() string {
	// TODO: used by daemon status. Drop this?
	return ""
}
