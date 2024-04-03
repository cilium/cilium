package tables

import (
	"net"

	"github.com/spf13/pflag"
	"k8s.io/apimachinery/pkg/util/sets"

	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/hive/job"
	"github.com/cilium/cilium/pkg/k8s"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/option"
	serviceStore "github.com/cilium/cilium/pkg/service/store"
	"github.com/cilium/cilium/pkg/source"
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
	Services       *Services
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
	// TODO: used by redirect manager and restoration. Point of this is to "undo" the direct
	// manipulation via ServiceManager. Fix this by removing all the other UpsertService calls
	// to ServiceManager and always go via the Table[Service].

	txn := s.params.Services.WriteTxn()
	defer txn.Commit()

	svc, _, found := s.params.ServiceTable.First(txn, ServiceNameIndex.Query(svcID))
	if found {
		// Do a no-op modification to force UpsertService()
		s.params.Services.UpsertService(txn, svc.Name, svc.ServiceParams)
	}
	return found
}

func (s *ServiceCache) GetServiceIP(svcID k8s.ServiceID) *loadbalancer.L3n4Addr {
	// TODO does it matter if it is ipv4 or ipv6? check EnableIPv6? or should
	// we filter already when ingesting k8s services?

	iter, _ := s.params.ServiceTable.Get(s.params.DB.ReadTxn(), ServiceNameIndex.Query(svcID))
	for svc, _, ok := iter.Next(); ok; svc, _, ok = iter.Next() {
		if svc.Type == loadbalancer.SVCTypeClusterIP {
			addr := svc.L3n4Addr
			// String representation may be used for dialing so set the scope
			// to external.
			addr.Scope = loadbalancer.ScopeExternal
			return &addr
		}
	}
	return nil
}

func (s *ServiceCache) MergeExternalServiceUpdate(service *serviceStore.ClusterService, swg *lock.StoppableWaitGroup) {
	// NOTE: used by clustermesh

	// TODO: the swg is used to block initRestore and thus SyncWithK8sFinished from pruning BPF maps. This should
	// instead be eventually resolved with the table initializers which would stop the pruning.
	// If we want a short-term workaround we would need to watch the Service.BPFStatus and wait for it to be marked
	// done, but for that need to rewrite daemon/controllers/service.go as a reconciler.

	// Ignore updates of own cluster
	if service.Cluster == option.Config.ClusterName {
		return
	}

	txn := s.params.Services.WriteTxn()
	defer txn.Commit()

	name := loadbalancer.ServiceName{
		Name:      service.Name,
		Namespace: service.Namespace,
		// TODO: cluster-aware?
		// Cluster: service.Cluster
	}

	backends := []BackendParams{}
	for ipString, ports := range service.Backends {
		addr, err := cmtypes.ParseAddrCluster(ipString)
		if err != nil {
			panic("TODO log bad IP")
		}
		for portName, l4Addr := range ports {
			params := BackendParams{
				Source: source.KVStore,
				Backend: loadbalancer.Backend{
					L3n4Addr:   loadbalancer.L3n4Addr{AddrCluster: addr, L4Addr: *l4Addr},
					NodeName:   "",
					FEPortName: portName,
					Weight:     loadbalancer.DefaultBackendWeight,
					State:      loadbalancer.BackendStateActive,
				},
			}
			backends = append(backends, params)
		}
	}
	err := s.params.Services.UpsertBackends(
		txn,
		name,
		backends...,
	)
	if err != nil {
		panic("UpsertBackends conflict")
	}
}

func (s *ServiceCache) MergeExternalServiceDelete(service *serviceStore.ClusterService, swg *lock.StoppableWaitGroup) {
	// TODO: used by clustermesh

	// Ignore updates of own cluster
	if service.Cluster == option.Config.ClusterName {
		return
	}

	txn := s.params.Services.WriteTxn()
	defer txn.Commit()

	name := loadbalancer.ServiceName{
		Name:      service.Name,
		Namespace: service.Namespace,
		// TODO: cluster-aware?
		// Cluster: service.Cluster
	}

	for ipString, ports := range service.Backends {
		addr, err := cmtypes.ParseAddrCluster(ipString)
		if err != nil {
			panic("TODO log bad IP")
		}
		for _, l4Addr := range ports {
			l3n4Addr := loadbalancer.L3n4Addr{AddrCluster: addr, L4Addr: *l4Addr}
			err := s.params.Services.DeleteBackend(txn, name, l3n4Addr)
			if err != nil {
				panic("DeleteBackend fail")
			}
		}
	}
}

func parseClusterService(svc *serviceStore.ClusterService) (out []*ServiceParams) {
	proto := ServiceParams{
		L3n4Addr: loadbalancer.L3n4Addr{},
		Type:     loadbalancer.SVCTypeClusterIP,
		Labels:   labels.Map2Labels(svc.Labels, "kvstore"),
		// svc.Selector?
		Source:    source.KVStore,
		ExtPolicy: loadbalancer.SVCTrafficPolicyCluster,
		IntPolicy: loadbalancer.SVCTrafficPolicyCluster,
	}
	for ipStr, ports := range svc.Frontends {
		svc := proto
		addr, err := cmtypes.ParseAddrCluster(ipStr)
		if err != nil {
			panic("TODO ParseAddrCluster error")
		}
		for name, port := range ports {
			l4Addr := loadbalancer.NewL4Addr(loadbalancer.L4Type(port.Protocol), uint16(port.Port))
			svc.PortName = loadbalancer.FEPortName(name)
			svc.L3n4Addr = loadbalancer.L3n4Addr{
				AddrCluster: addr,
				L4Addr:      *l4Addr,
			}
			out = append(out, &svc)
		}
	}
	return

}

func (s *ServiceCache) MergeClusterServiceUpdate(service *serviceStore.ClusterService, swg *lock.StoppableWaitGroup) {
	// TODO: used by clustermesh

	name := loadbalancer.ServiceName{
		Name:      service.Name,
		Namespace: service.Namespace,
		// TODO: cluster-aware?
		// Cluster: service.Cluster
	}

	// Insert the backends after the service
	// TODO split MergeExternalServiceUpdate and don't do separate WriteTxn
	defer s.MergeExternalServiceUpdate(service, swg)

	txn := s.params.Services.WriteTxn()
	defer txn.Commit()
	for _, p := range parseClusterService(service) {
		err := s.params.Services.UpsertService(txn, name, p)
		if err != nil {
			panic("TODO UpsertService error")
		}
	}

}

func (s *ServiceCache) MergeClusterServiceDelete(service *serviceStore.ClusterService, swg *lock.StoppableWaitGroup) {
	// TODO: used by clustermesh
	name := loadbalancer.ServiceName{
		Name:      service.Name,
		Namespace: service.Namespace,
		// TODO: cluster-aware?
		// Cluster: service.Cluster
	}

	defer s.MergeExternalServiceDelete(service, swg)

	txn := s.params.Services.WriteTxn()
	defer txn.Commit()

	// FIXME delete everything by name or just the entries referred to
	// by 'service'?
	s.params.Services.DeleteServicesByName(txn, name, source.KVStore)
}

func (s *ServiceCache) GetServiceAddrsWithType(svcID k8s.ServiceID,
	svcType loadbalancer.SVCType) (map[loadbalancer.FEPortName][]*loadbalancer.L3n4Addr, int) {
	// NOTE: used by redirect manager

	numIPs := 0
	addrs := map[loadbalancer.FEPortName][]*loadbalancer.L3n4Addr{}
	iter, _ := s.params.ServiceTable.Get(s.params.DB.ReadTxn(), ServiceNameIndex.Query(svcID))
	for svc, _, ok := iter.Next(); ok; svc, _, ok = iter.Next() {
		if svc.Type == svcType {
			addrs[svc.PortName] = append(addrs[svc.PortName], &svc.L3n4Addr)
			numIPs++
		}
	}
	return addrs, numIPs
}

func (s *ServiceCache) GetServiceFrontendIP(svcID k8s.ServiceID, svcType loadbalancer.SVCType) net.IP {
	// NOTE: used by redirect manager
	iter, _ := s.params.ServiceTable.Get(s.params.DB.ReadTxn(), ServiceNameIndex.Query(svcID))
	for svc, _, ok := iter.Next(); ok; svc, _, ok = iter.Next() {
		if svc.Type == svcType {
			return svc.L3n4Addr.AddrCluster.AsNetIP()
		}
	}
	return nil
}

func (s *ServiceCache) GetEndpointsOfService(svcID k8s.ServiceID) *k8s.Endpoints {
	// TODO: used by BGP. Rewrite it to use Table[Backend]

	endpoints := k8s.NewEndpoints()
	iter, _ := s.params.BackendTable.Get(s.params.DB.ReadTxn(), BackendServiceIndex.Query(svcID))
	for be, _, ok := iter.Next(); ok; be, _, ok = iter.Next() {
		be2 := endpoints.Backends[be.L3n4Addr.AddrCluster]
		if be2 == nil {
			be2 = &k8s.Backend{
				Ports:         map[string]*loadbalancer.L4Addr{},
				NodeName:      be.NodeName,
				Terminating:   be.State == loadbalancer.BackendStateTerminating,
				HintsForZones: be.HintsForZones,
				Preferred:     false,
			}
			endpoints.Backends[be.L3n4Addr.AddrCluster] = be2
		}
		be2.Ports[be.FEPortName] = &be.L3n4Addr.L4Addr
	}
	if len(endpoints.Backends) == 0 {
		return nil
	}
	return endpoints
}

func (s *ServiceCache) LocalServices() sets.Set[k8s.ServiceID] {
	// TODO: used by lbmap post-restoration cleanup. Need to look into how this should work.
	// Currently daemon/controllers/service.go won't block Daemon.initRestore and thus this
	// will be likely used too early. Should use the "table initializers" functionality
	// in cilium/statedb and the daemon/controllers/service.go should be the one calling
	// SyncWithK8sFinished.

	iter, _ := s.params.ServiceTable.All(s.params.DB.ReadTxn())
	return statedb.CollectSet(statedb.Map(iter, func(svc *Service) k8s.ServiceID {
		return svc.Name
	}))
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
