// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package experimental

import (
	"iter"
	"log/slog"
	"net"
	"net/netip"

	"github.com/cilium/hive/cell"
	"github.com/cilium/statedb"
	"github.com/cilium/statedb/reconciler"
	"github.com/cilium/stream"
	"k8s.io/apimachinery/pkg/util/sets"

	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/k8s"
	v1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/service"
	"github.com/cilium/cilium/pkg/service/store"
	"github.com/cilium/cilium/pkg/source"
	"github.com/cilium/cilium/pkg/time"
)

// The adapters in this file replace the [k8s.ServiceCacheReader] and [service.ServiceReader]
// implementations when the experimental load-balancing is enabled. These are meant to be
// temporary until the uses of these interfaces have been migrated over to using the tables
// directly.

type adapterParams struct {
	cell.In

	Log       *slog.Logger
	Config    Config
	DB        *statedb.DB
	Services  statedb.Table[*Service]
	Backends  statedb.Table[*Backend]
	Frontends statedb.Table[*Frontend]
	Ops       *BPFOps
	Writer    *Writer

	SC k8s.ServiceCache       `optional:"true"`
	SM service.ServiceManager `optional:"true"`
}

func decorateAdapters(p adapterParams) (sc k8s.ServiceCache, sm service.ServiceManager) {
	if !p.Config.EnableExperimentalLB {
		return p.SC, p.SM
	}
	sc = &serviceCacheAdapter{
		log:      p.Log,
		db:       p.DB,
		services: p.Services,
		backends: p.Backends,
		writer:   p.Writer,
	}
	sm = &serviceManagerAdapter{
		log:       p.Log,
		db:        p.DB,
		services:  p.Services,
		frontends: p.Frontends,
	}
	return
}

type serviceCacheAdapter struct {
	log      *slog.Logger
	db       *statedb.DB
	services statedb.Table[*Service]
	backends statedb.Table[*Backend]
	writer   *Writer
}

// DebugStatus implements k8s.ServiceCache.
func (s *serviceCacheAdapter) DebugStatus() string {
	return "<experimental.serviceCacheAdapter>"
}

// DeleteEndpoints implements k8s.ServiceCache.
func (s *serviceCacheAdapter) DeleteEndpoints(svcID k8s.EndpointSliceID, swg *lock.StoppableWaitGroup) k8s.ServiceID {
	s.log.Debug("serviceCacheAdapter: Ignoring DeleteEndpoints", "svcID", svcID)
	return k8s.ServiceID{}
}

// DeleteService implements k8s.ServiceCache.
func (s *serviceCacheAdapter) DeleteService(k8sSvc *v1.Service, swg *lock.StoppableWaitGroup) {
	s.log.Debug("serviceCacheAdapter: Ignoring DeleteService", "name", k8sSvc.Namespace+"/"+k8sSvc.Name)
}

// EnsureService implements k8s.ServiceCache.
func (s *serviceCacheAdapter) EnsureService(svcID k8s.ServiceID, swg *lock.StoppableWaitGroup) bool {
	s.log.Debug("serviceCacheAdapter: Ignoring EnsureService", "svcID", svcID)
	return true
}

// Events implements k8s.ServiceCache.
func (s *serviceCacheAdapter) Events() <-chan k8s.ServiceEvent {
	return make(chan k8s.ServiceEvent)
}

// GetServiceAddrsWithType implements k8s.ServiceCache.
func (s *serviceCacheAdapter) GetServiceAddrsWithType(svcID k8s.ServiceID, svcType loadbalancer.SVCType) (map[loadbalancer.FEPortName][]*loadbalancer.L3n4Addr, int) {
	// Used by LRP, which is not used when new implementation is enabled.
	panic("unimplemented")
}

// GetServiceFrontendIP implements k8s.ServiceCache.
func (s *serviceCacheAdapter) GetServiceFrontendIP(svcID k8s.ServiceID, svcType loadbalancer.SVCType) net.IP {
	// Used by LRP, which is not used when new implementation is enabled.
	panic("unimplemented")
}

// LocalServices implements k8s.ServiceCache.
func (s *serviceCacheAdapter) LocalServices() sets.Set[k8s.ServiceID] {
	// Used for the "two-phase GC" of services with ClusterMesh, e.g. the cluster-local services are GCd first
	// to clean up any stale info about clustermesh etcd endpoints and then the second phase cleans up everything.
	// This method is used to return the services that are cluster-local.
	// With the new implementation this "two-phase GC" is not needed as the new implementation does not restore
	// services from BPF maps but updates them directly and later prunes once both k8s and ClusterMesh has synced.
	return nil
}

// MergeClusterServiceDelete implements k8s.ServiceCache.
func (s *serviceCacheAdapter) MergeClusterServiceDelete(service *store.ClusterService, swg *lock.StoppableWaitGroup) {
	name := loadbalancer.ServiceName{
		Namespace: service.Namespace,
		Name:      service.Name,
		Cluster:   service.Cluster,
	}
	txn := s.writer.WriteTxn()
	defer txn.Commit()
	s.writer.DeleteServiceAndFrontends(
		txn,
		name,
	)
}

// MergeClusterServiceUpdate implements k8s.ServiceCache.
func (s *serviceCacheAdapter) MergeClusterServiceUpdate(service *store.ClusterService, swg *lock.StoppableWaitGroup) {
	svc, fes := clusterServiceToServiceAndFrontends(service)

	txn := s.writer.WriteTxn()
	defer txn.Commit()
	s.writer.UpsertServiceAndFrontends(
		txn,
		svc,
		fes...,
	)
}

// MergeExternalServiceDelete implements k8s.ServiceCache.
func (s *serviceCacheAdapter) MergeExternalServiceDelete(service *store.ClusterService, swg *lock.StoppableWaitGroup) {
	if service.Cluster == option.Config.ClusterName {
		// Ignore updates of own cluster
		return
	}
	name := loadbalancer.ServiceName{
		Namespace: service.Namespace,
		Name:      service.Name,
		Cluster:   service.Cluster,
	}
	txn := s.writer.WriteTxn()
	defer txn.Commit()
	s.writer.DeleteBackendsOfService(
		txn,
		name,
		source.ClusterMesh,
	)
}

// MergeExternalServiceUpdate implements k8s.ServiceCache.
func (s *serviceCacheAdapter) MergeExternalServiceUpdate(service *store.ClusterService, swg *lock.StoppableWaitGroup) {
	if service.Cluster == option.Config.ClusterName {
		// Ignore updates of own cluster
		return
	}

	name := loadbalancer.ServiceName{
		Namespace: service.Namespace,
		Name:      service.Name,
		Cluster:   service.Cluster,
	}

	backends := clusterServiceToBackendParams(service)
	txn := s.writer.WriteTxn()
	defer txn.Commit()
	s.writer.UpsertBackends(
		txn,
		name,
		source.ClusterMesh,
		backends...,
	)
}

func clusterServiceToBackendParams(service *store.ClusterService) (beps []BackendParams) {
	for ipString, portConfig := range service.Backends {
		addrCluster, err := cmtypes.ParseAddrCluster(ipString)
		if err != nil {
			continue
		}
		for name, l4 := range portConfig {
			bep := BackendParams{
				L3n4Addr: loadbalancer.L3n4Addr{
					AddrCluster: addrCluster,
					L4Addr:      *l4,
				},
				PortName: name,
				Weight:   0,
				NodeName: "",
				ZoneID:   0,
				State:    loadbalancer.BackendStateActive,
			}
			beps = append(beps, bep)
		}
	}
	return
}

func clusterServiceToServiceAndFrontends(csvc *store.ClusterService) (*Service, []FrontendParams) {
	name := loadbalancer.ServiceName{
		Cluster:   csvc.Cluster,
		Name:      csvc.Name,
		Namespace: csvc.Namespace,
	}
	svc := &Service{
		Name:             name,
		Source:           source.KVStore,
		Labels:           labels.Map2Labels(csvc.Labels, string(source.KVStore)),
		Selector:         csvc.Selector,
		NatPolicy:        loadbalancer.SVCNatPolicyNone,
		ExtTrafficPolicy: loadbalancer.SVCTrafficPolicyCluster,
		IntTrafficPolicy: loadbalancer.SVCTrafficPolicyCluster,
	}

	fes := make([]FrontendParams, 0, len(csvc.Frontends))
	for ipStr, ports := range csvc.Frontends {
		addrCluster, err := cmtypes.ParseAddrCluster(ipStr)
		if err != nil {
			continue
		}
		for name, port := range ports {
			l4 := loadbalancer.NewL4Addr(loadbalancer.L4Type(port.Protocol), uint16(port.Port))
			portName := loadbalancer.FEPortName(name)

			fes = append(fes,
				FrontendParams{
					Address: loadbalancer.L3n4Addr{
						AddrCluster: addrCluster,
						L4Addr:      *l4,
					},
					Type:        loadbalancer.SVCTypeClusterIP,
					ServiceName: loadbalancer.ServiceName{},
					PortName:    portName,
					ServicePort: l4.Port,
				},
			)
		}
	}
	return svc, fes
}

// UpdateEndpoints implements k8s.ServiceCache.
func (s *serviceCacheAdapter) UpdateEndpoints(newEndpoints *k8s.Endpoints, swg *lock.StoppableWaitGroup) (k8s.ServiceID, *k8s.Endpoints) {
	s.log.Debug("serviceCacheAdapter: Ignoring UpdateEndpoints", "name", newEndpoints.Namespace+"/"+newEndpoints.Name)
	return k8s.ServiceID{}, newEndpoints
}

// UpdateService implements k8s.ServiceCache.
func (s *serviceCacheAdapter) UpdateService(k8sSvc *v1.Service, swg *lock.StoppableWaitGroup) k8s.ServiceID {
	s.log.Debug("serviceCacheAdapter: Ignoring UpdateService", "name", k8sSvc.Namespace+"/"+k8sSvc.Name)
	return k8s.ServiceID{}
}

func newMinimalService(svc *Service) *k8s.MinimalService {
	return &k8s.MinimalService{
		Labels:      svc.Labels.K8sStringMap(),
		Annotations: svc.Annotations,
		Selector:    svc.Selector,
	}
}

func newMinimalEndpoints(svcName loadbalancer.ServiceName, backends iter.Seq[*Backend]) *k8s.MinimalEndpoints {
	eps := &k8s.MinimalEndpoints{
		Backends: map[cmtypes.AddrCluster]store.PortConfiguration{},
	}
	for be := range backends {
		ports, ok := eps.Backends[be.AddrCluster]
		if !ok {
			ports = store.PortConfiguration{}
			eps.Backends[be.AddrCluster] = ports
		}
		inst := be.GetInstance(svcName)
		ports[inst.PortName] = &be.L4Addr
	}
	return eps
}

// ForEachService implements k8s.ServiceCacheReader.
func (s *serviceCacheAdapter) ForEachService(yield func(svcID k8s.ServiceID, svc *k8s.MinimalService, eps *k8s.MinimalEndpoints) bool) {
	txn := s.db.ReadTxn()

	for svc := range s.services.All(txn) {
		backends := statedb.ToSeq(s.backends.List(txn, BackendByServiceName(svc.Name)))
		yield(
			k8s.ServiceID{
				Cluster:   svc.Name.Cluster,
				Name:      svc.Name.Name,
				Namespace: svc.Name.Namespace,
			},
			newMinimalService(svc),
			newMinimalEndpoints(svc.Name, backends),
		)
	}
}

// Notifications implements k8s.ServiceCacheReader.
func (s *serviceCacheAdapter) Notifications() stream.Observable[k8s.ServiceNotification] {
	notifications, emit, complete := stream.Multicast[k8s.ServiceNotification]()

	go func() {
		state := map[loadbalancer.ServiceName]*k8s.ServiceNotification{}
		get := func(name loadbalancer.ServiceName) *k8s.ServiceNotification {
			n, ok := state[name]
			if !ok {
				n = &k8s.ServiceNotification{}
				state[name] = n
			}
			return n
		}

		wtxn := s.db.WriteTxn(s.services, s.backends)
		defer wtxn.Abort()
		serviceChanges, err := s.services.Changes(wtxn)
		if err != nil {
			complete(err)
			return
		}
		backendChanges, err := s.backends.Changes(wtxn)
		if err != nil {
			complete(err)
			return
		}
		wtxn.Commit()
		defer complete(nil)

		for {
			txn := s.db.ReadTxn()
			changed := sets.Set[loadbalancer.ServiceName]{}

			services, watchServices := serviceChanges.Next(txn)
			for ev := range services {
				svc := ev.Object
				n := get(svc.Name)
				n.Service = newMinimalService(svc)
				if ev.Deleted {
					n.Action = k8s.DeleteService
				} else {
					n.Action = k8s.UpdateService
				}
				changed.Insert(svc.Name)
			}

			backends, watchBackends := backendChanges.Next(txn)
			for ev := range backends {
				be := ev.Object
				for inst := range be.Instances.All() {
					changed.Insert(inst.ServiceName)
				}
			}

			for name := range changed {
				n := get(name)
				backends := statedb.ToSeq(s.backends.List(txn, BackendByServiceName(name)))
				n.Endpoints = newMinimalEndpoints(name, backends)
				emit(*n)

				if n.Action == k8s.DeleteService {
					delete(state, name)
				} else {
					n.OldService = n.Service
					n.Service = nil
					n.OldEndpoints = n.Endpoints
					n.Endpoints = nil
				}
			}

			select {
			case <-watchServices:
			case <-watchBackends:
			}
		}

	}()

	return notifications
}

var _ k8s.ServiceCacheReader = &serviceCacheAdapter{}

var _ k8s.ServiceCache = &serviceCacheAdapter{}

type serviceManagerAdapter struct {
	log       *slog.Logger
	db        *statedb.DB
	services  statedb.Table[*Service]
	frontends statedb.Table[*Frontend]
}

// DeleteService implements service.ServiceManager.
func (s *serviceManagerAdapter) DeleteService(frontend loadbalancer.L3n4Addr) (bool, error) {
	s.log.Debug("serviceManagerAdapter: Ignoring DeleteService", "frontend", frontend.StringWithProtocol())
	return true, nil
}

// DeleteServiceByID implements service.ServiceManager.
func (s *serviceManagerAdapter) DeleteServiceByID(id loadbalancer.ServiceID) (bool, error) {
	// Used by REST API.
	s.log.Debug("serviceManagerAdapter: Ignoring DeleteServiceByID", "id", id)
	return true, nil
}

// DeregisterL7LBServiceBackendSync implements service.ServiceManager.
func (s *serviceManagerAdapter) DeregisterL7LBServiceBackendSync(serviceName loadbalancer.ServiceName, backendSyncRegistration service.BackendSyncer) error {
	// Used by ciliumenvoyconfig, but not when new implementation is enabled.
	panic("unimplemented")
}

// DeregisterL7LBServiceRedirect implements service.ServiceManager.
func (s *serviceManagerAdapter) DeregisterL7LBServiceRedirect(serviceName loadbalancer.ServiceName, resourceName service.L7LBResourceName) error {
	// Used by ciliumenvoyconfig, but not when new implementation is enabled.
	panic("unimplemented")
}

// GetCurrentTs implements service.ServiceManager.
func (s *serviceManagerAdapter) GetCurrentTs() time.Time {
	// Used by kubeproxyhealthz.
	return time.Now()
}

// GetDeepCopyServiceByFrontend implements service.ServiceManager.
func (s *serviceManagerAdapter) GetDeepCopyServiceByFrontend(frontend loadbalancer.L3n4Addr) (*loadbalancer.SVC, bool) {
	// Used by pod watcher, which will be replaced when new implementation is enabled.
	return nil, false
}

// GetDeepCopyServiceByID implements service.ServiceManager.
func (s *serviceManagerAdapter) GetDeepCopyServiceByID(id loadbalancer.ServiceID) (*loadbalancer.SVC, bool) {
	// Used by REST API
	return nil, false
}

// GetDeepCopyServices implements service.ServiceManager.
func (s *serviceManagerAdapter) GetDeepCopyServices() (svcs []*loadbalancer.SVC) {
	// Used by REST API.
	txn := s.db.ReadTxn()
	for fe := range s.frontends.All(txn) {
		bes := []*loadbalancer.Backend{}
		svc := fe.service
		for be := range fe.Backends {
			inst := be.GetInstance(fe.ServiceName)
			bes = append(bes, &loadbalancer.Backend{
				FEPortName: inst.PortName,
				ID:         0,
				Weight:     inst.Weight,
				NodeName:   be.NodeName,
				ZoneID:     be.ZoneID,
				L3n4Addr:   be.L3n4Addr,
				State:      inst.State,
				Preferred:  true,
			})
		}
		proxyPort := uint16(0)
		if svc.ProxyRedirect != nil {
			proxyPort = svc.ProxyRedirect.ProxyPort
		}
		svcModel := &loadbalancer.SVC{
			Frontend: loadbalancer.L3n4AddrID{
				L3n4Addr: fe.Address,
				ID:       loadbalancer.ID(fe.ID),
			},
			Type:        fe.Type,
			Name:        fe.ServiceName,
			Annotations: fe.service.Annotations,
			Backends:    bes,

			ForwardingMode:            "", // FIXME (not implemented)
			ExtTrafficPolicy:          svc.ExtTrafficPolicy,
			IntTrafficPolicy:          svc.IntTrafficPolicy,
			NatPolicy:                 svc.NatPolicy,
			SourceRangesPolicy:        "", // FIXME (not implemented)
			SessionAffinity:           svc.SessionAffinity,
			SessionAffinityTimeoutSec: uint32(svc.SessionAffinityTimeout),
			HealthCheckNodePort:       svc.HealthCheckNodePort,
			LoadBalancerAlgorithm:     0,   // FIXME (not merged yet)
			LoadBalancerSourceRanges:  nil, // FIXME CIDR vs *CIDR
			L7LBProxyPort:             proxyPort,
			LoopbackHostport:          svc.LoopbackHostPort,
		}
		svcs = append(svcs, svcModel)
	}
	return
}

// GetLastUpdatedTs implements service.ServiceManager.
func (s *serviceManagerAdapter) GetLastUpdatedTs() time.Time {
	// Used by kubeproxyhealthz. Unclear how important it is to have real last updated time here.
	// We could e.g. keep a timestamp behind an atomic in BPFOps to implement that.
	return time.Now()
}

// InitMaps implements service.ServiceManager.
func (s *serviceManagerAdapter) InitMaps(ipv6 bool, ipv4 bool, sockMaps bool, restore bool) error {
	// No need for this since new implementation manages its own maps. Called from daemon/cmd/datapath.go.
	s.log.Debug("serviceManagerAdapter: Ignoring InitMaps")
	return nil
}

// RegisterL7LBServiceBackendSync implements service.ServiceManager.
func (s *serviceManagerAdapter) RegisterL7LBServiceBackendSync(serviceName loadbalancer.ServiceName, backendSyncRegistration service.BackendSyncer) error {
	// Used by ciliumenvoyconfig, but not when new implementation is enabled.
	panic("unimplemented")
}

// RegisterL7LBServiceRedirect implements service.ServiceManager.
func (s *serviceManagerAdapter) RegisterL7LBServiceRedirect(serviceName loadbalancer.ServiceName, resourceName service.L7LBResourceName, proxyPort uint16, frontendPorts []uint16) error {
	// Used by ciliumenvoyconfig, but not when new implementation is enabled.
	panic("unimplemented")
}

// RestoreServices implements service.ServiceManager.
func (s *serviceManagerAdapter) RestoreServices() error {
	s.log.Debug("serviceManagerAdapter: Ignoring RestoreServices")
	return nil
}

// SyncNodePortFrontends implements service.ServiceManager.
func (s *serviceManagerAdapter) SyncNodePortFrontends(sets.Set[netip.Addr]) error {
	s.log.Debug("serviceManagerAdapter: Ignoring SyncNodePortFrontends")
	return nil
}

// SyncWithK8sFinished implements service.ServiceManager.
func (s *serviceManagerAdapter) SyncWithK8sFinished(localOnly bool, localServices sets.Set[k8s.ServiceID]) (stale []k8s.ServiceID, err error) {
	s.log.Debug("serviceManagerAdapter: Ignoring SyncWithK8sFinished")
	return
}

// TerminateUDPConnectionsToBackend implements service.ServiceManager.
func (s *serviceManagerAdapter) TerminateUDPConnectionsToBackend(l3n4Addr *loadbalancer.L3n4Addr) {
	// Used by LRP, but not when new implementation is enabled.
	panic("unimplemented")
}

// UpdateBackendsState implements service.ServiceManager.
func (s *serviceManagerAdapter) UpdateBackendsState(backends []*loadbalancer.Backend) ([]loadbalancer.L3n4Addr, error) {
	// Used by REST API.
	s.log.Debug("serviceManagerAdapter: Ignoring UpdateBackendsState")
	return nil, nil
}

// UpsertService implements service.ServiceManager.
func (s *serviceManagerAdapter) UpsertService(svc *loadbalancer.SVC) (bool, loadbalancer.ID, error) {
	// Used by pod watcher, LRP and REST API
	s.log.Debug("serviceManagerAdapter: Ignoring UpsertService", "name", svc.Name)
	return true, 0, nil
}

// GetServiceIDs implements service.ServiceReader.
func (s *serviceManagerAdapter) GetServiceIDs() []loadbalancer.ServiceID {
	// Used by pkg/act.

	txn := s.db.ReadTxn()
	ids := make([]loadbalancer.ServiceID, 0, s.frontends.NumObjects(txn))
	for fe := range s.frontends.All(txn) {
		if fe.Status.Kind == reconciler.StatusKindDone {
			ids = append(ids, fe.ID)
		}
	}
	return ids
}

// GetServiceNameByAddr implements service.ServiceReader.
func (s *serviceManagerAdapter) GetServiceNameByAddr(addr loadbalancer.L3n4Addr) (string, string, bool) {
	// Used by hubble.

	txn := s.db.ReadTxn()

	fe, _, found := s.frontends.Get(txn, FrontendByAddress(addr))
	if !found {
		return "", "", false
	}
	return fe.service.Name.Namespace, fe.service.Name.Name, true
}

var _ service.ServiceManager = &serviceManagerAdapter{}
