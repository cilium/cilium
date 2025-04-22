// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cell

import (
	"context"
	"iter"
	"log/slog"
	"net"
	"net/netip"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"
	"github.com/cilium/statedb/reconciler"
	"github.com/cilium/stream"
	"k8s.io/apimachinery/pkg/util/sets"

	"github.com/cilium/cilium/pkg/clustermesh/store"
	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/k8s"
	v1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/loadbalancer/legacy/service"
	lbreconciler "github.com/cilium/cilium/pkg/loadbalancer/reconciler"
	"github.com/cilium/cilium/pkg/loadbalancer/writer"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/time"
)

// The adapters in this file replace the [k8s.ServiceCacheReader] and [service.ServiceReader]
// implementations when the experimental load-balancing is enabled. These are meant to be
// temporary until the uses of these interfaces have been migrated over to using the tables
// directly.

type adapterParams struct {
	cell.In

	JobGroup     job.Group
	Log          *slog.Logger
	DaemonConfig *option.DaemonConfig
	Config       loadbalancer.Config
	DB           *statedb.DB
	Services     statedb.Table[*loadbalancer.Service]
	Backends     statedb.Table[*loadbalancer.Backend]
	Frontends    statedb.Table[*loadbalancer.Frontend]
	Ops          *lbreconciler.BPFOps
	Writer       *writer.Writer
	TestConfig   *loadbalancer.TestConfig `optional:"true"`
}

type decorateParams struct {
	cell.In

	Config loadbalancer.Config
	SCA    *serviceCacheAdapter
	SC     k8s.ServiceCache `optional:"true"`
	SMA    *serviceManagerAdapter
	SM     service.ServiceManager `optional:"true"`
}

func decorateAdapters(p decorateParams) (k8s.ServiceCache, service.ServiceManager) {
	if !p.Config.EnableExperimentalLB {
		return p.SC, p.SM
	}
	return p.SCA, p.SMA
}

// newAdapters constructs the ServiceCache and ServiceManager adapters. This is separate
// from [decorateAdapters] in order to have access to the module's job.Group which is not
// accessible in the [cell.DecorateAll] scope.
func newAdapters(p adapterParams) (sca *serviceCacheAdapter, sma *serviceManagerAdapter) {
	if !p.Config.EnableExperimentalLB {
		return nil, nil
	}
	sca = &serviceCacheAdapter{
		log:      p.Log,
		db:       p.DB,
		services: p.Services,
		backends: p.Backends,
		writer:   p.Writer,
	}
	sca.notifications, sca.emit, sca.complete = stream.Multicast[k8s.ServiceNotification]()
	p.JobGroup.Add(job.OneShot("adapter-notifications", sca.feedNotifications))

	// If we are not running in tests we should register a table initializer to
	// delay pruning until ClusterMesh has catched up. This happens via
	// (*Daemon).initRestore in daemon/cmd/state.go. Once ClusterMesh has switched
	// to using the Writer directly this can be removed.
	var initDone func(writer.WriteTxn)
	if p.TestConfig == nil {
		initDone = p.Writer.RegisterInitializer("adapters")
	} else {
		initDone = func(writer.WriteTxn) {}
	}
	sma = &serviceManagerAdapter{
		log:          p.Log,
		daemonConfig: p.DaemonConfig,
		db:           p.DB,
		services:     p.Services,
		frontends:    p.Frontends,
		writer:       p.Writer,
		initDone:     initDone,
	}
	return
}

type serviceCacheAdapter struct {
	log           *slog.Logger
	db            *statedb.DB
	services      statedb.Table[*loadbalancer.Service]
	backends      statedb.Table[*loadbalancer.Backend]
	writer        *writer.Writer
	notifications stream.Observable[k8s.ServiceNotification]
	emit          func(k8s.ServiceNotification)
	complete      func(error)
}

// DebugStatus implements k8s.ServiceCache.
func (s *serviceCacheAdapter) DebugStatus() string {
	return "<experimental.serviceCacheAdapter>"
}

// DeleteEndpoints implements k8s.ServiceCache.
func (s *serviceCacheAdapter) DeleteEndpoints(svcID k8s.EndpointSliceID, swg *lock.StoppableWaitGroup) k8s.ServiceID {
	s.log.Debug("serviceCacheAdapter: Ignoring DeleteEndpoints", logfields.ServiceID, svcID)
	return k8s.ServiceID{}
}

// DeleteService implements k8s.ServiceCache.
func (s *serviceCacheAdapter) DeleteService(k8sSvc *v1.Service, swg *lock.StoppableWaitGroup) {
	s.log.Debug("serviceCacheAdapter: Ignoring DeleteService", logfields.Name, k8sSvc.Namespace+"/"+k8sSvc.Name)
}

// EnsureService implements k8s.ServiceCache.
func (s *serviceCacheAdapter) EnsureService(svcID k8s.ServiceID, swg *lock.StoppableWaitGroup) bool {
	s.log.Debug("serviceCacheAdapter: Ignoring EnsureService", logfields.ServiceID, svcID)
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

// MergeExternalServiceDelete implements k8s.ServiceCache.
func (s *serviceCacheAdapter) MergeExternalServiceDelete(service *store.ClusterService, swg *lock.StoppableWaitGroup) {
	// pkg/clustermesh/service_merger.go implements this for experimental control-plane.
	panic("unimplemented")
}

// MergeExternalServiceUpdate implements k8s.ServiceCache.
func (s *serviceCacheAdapter) MergeExternalServiceUpdate(service *store.ClusterService, swg *lock.StoppableWaitGroup) {
	// pkg/clustermesh/service_merger.go implements this for experimental control-plane.
	panic("unimplemented")
}

// UpdateEndpoints implements k8s.ServiceCache.
func (s *serviceCacheAdapter) UpdateEndpoints(newEndpoints *k8s.Endpoints, swg *lock.StoppableWaitGroup) (k8s.ServiceID, *k8s.Endpoints) {
	s.log.Debug("serviceCacheAdapter: Ignoring UpdateEndpoints", logfields.Name, newEndpoints.Namespace+"/"+newEndpoints.Name)
	return k8s.ServiceID{}, newEndpoints
}

// UpdateService implements k8s.ServiceCache.
func (s *serviceCacheAdapter) UpdateService(k8sSvc *v1.Service, swg *lock.StoppableWaitGroup) k8s.ServiceID {
	s.log.Debug("serviceCacheAdapter: Ignoring UpdateService", logfields.Name, k8sSvc.Namespace+"/"+k8sSvc.Name)
	return k8s.ServiceID{}
}

func newMinimalService(svc *loadbalancer.Service) *k8s.MinimalService {
	return &k8s.MinimalService{
		Labels:      svc.Labels.K8sStringMap(),
		Annotations: svc.Annotations,
		Selector:    svc.Selector,
	}
}

func newMinimalEndpoints(svcName loadbalancer.ServiceName, backends iter.Seq[*loadbalancer.Backend]) *k8s.MinimalEndpoints {
	eps := &k8s.MinimalEndpoints{
		Backends: map[cmtypes.AddrCluster]store.PortConfiguration{},
	}
	for be := range backends {
		inst := be.GetInstance(svcName)
		if inst == nil {
			continue
		}
		ports, ok := eps.Backends[be.Address.AddrCluster]
		if !ok {
			ports = store.PortConfiguration{}
			eps.Backends[be.Address.AddrCluster] = ports
		}
		if len(inst.PortNames) == 0 {
			ports[""] = &be.Address.L4Addr
		} else {
			for _, portName := range inst.PortNames {
				ports[portName] = &be.Address.L4Addr
			}
		}
	}
	return eps
}

// ForEachService implements k8s.ServiceCacheReader.
func (s *serviceCacheAdapter) ForEachService(yield func(svcID k8s.ServiceID, svc *k8s.MinimalService, eps *k8s.MinimalEndpoints) bool) {
	txn := s.db.ReadTxn()

	for svc := range s.services.All(txn) {
		backends := statedb.ToSeq(s.backends.List(txn, loadbalancer.BackendByServiceName(svc.Name)))
		if !yield(
			k8s.ServiceID{
				Cluster:   svc.Name.Cluster,
				Name:      svc.Name.Name,
				Namespace: svc.Name.Namespace,
			},
			newMinimalService(svc),
			newMinimalEndpoints(svc.Name, backends),
		) {
			return
		}
	}
}

// Notifications implements k8s.ServiceCacheReader.
func (s *serviceCacheAdapter) Notifications() stream.Observable[k8s.ServiceNotification] {
	return s.notifications
}

// Notifications implements k8s.ServiceCacheReader.
func (s *serviceCacheAdapter) feedNotifications(ctx context.Context, _ cell.Health) error {
	state := map[loadbalancer.ServiceName]*k8s.ServiceNotification{}

	wtxn := s.db.WriteTxn(s.services, s.backends)
	defer wtxn.Abort()
	serviceChanges, err := s.services.Changes(wtxn)
	if err != nil {
		s.complete(err)
		return nil
	}
	backendChanges, err := s.backends.Changes(wtxn)
	if err != nil {
		s.complete(err)
		return nil
	}
	wtxn.Commit()
	defer s.complete(nil)

	for {
		txn := s.db.ReadTxn()

		// Collect the names of all changed services. Both a change to a service or to the
		// set of backends associated with a service is worthy of a notification.
		changed := sets.Set[loadbalancer.ServiceName]{}

		services, watchServices := serviceChanges.Next(txn)
		for ev := range services {
			changed.Insert(ev.Object.Name)
		}

		backends, watchBackends := backendChanges.Next(txn)
		for ev := range backends {
			be := ev.Object
			for inst := range be.Instances.All() {
				changed.Insert(inst.ServiceName)
			}
		}

		// For each changed service look it up along with the associated backends and
		// emit a notification for it.
		for name := range changed {
			// Look up the service and the previous notification we sent for it.
			n, stateFound := state[name]
			svc, _, found := s.services.Get(txn, loadbalancer.ServiceByName(name))

			// If no previously sent notification is found then no need to emit anything
			// for the deletion.
			if !found && !stateFound {
				continue
			}

			if found {
				if !stateFound {
					n = &k8s.ServiceNotification{
						ID: k8s.ServiceID{
							Cluster:   name.Cluster,
							Name:      name.Name,
							Namespace: name.Namespace,
						},
					}
					state[name] = n
				}
				n.Action = k8s.UpdateService
				n.OldService = n.Service
				n.OldEndpoints = n.Endpoints
				n.Service = newMinimalService(svc)
				backends := statedb.ToSeq(s.backends.List(txn, loadbalancer.BackendByServiceName(name)))
				n.Endpoints = newMinimalEndpoints(name, backends)
			} else {
				n.Action = k8s.DeleteService
				n.Service = n.OldService
				n.Endpoints = n.OldEndpoints
				n.OldService = nil
				n.OldEndpoints = nil
				delete(state, name)
			}

			s.emit(*n)
		}

		select {
		case <-watchServices:
		case <-watchBackends:
		case <-ctx.Done():
			return nil
		}
	}
}

var _ k8s.ServiceCache = &serviceCacheAdapter{}

type serviceManagerAdapter struct {
	log          *slog.Logger
	daemonConfig *option.DaemonConfig
	db           *statedb.DB
	services     statedb.Table[*loadbalancer.Service]
	frontends    statedb.Table[*loadbalancer.Frontend]
	writer       *writer.Writer

	initDone func(writer.WriteTxn)
}

// DeleteService implements service.ServiceManager.
func (s *serviceManagerAdapter) DeleteService(frontend loadbalancer.L3n4Addr) (bool, error) {
	s.log.Debug("serviceManagerAdapter: Ignoring DeleteService", logfields.Frontend, frontend.StringWithProtocol())
	return true, nil
}

// DeleteServiceByID implements service.ServiceManager.
func (s *serviceManagerAdapter) DeleteServiceByID(id loadbalancer.ServiceID) (bool, error) {
	// Used by REST API.
	s.log.Debug("serviceManagerAdapter: Ignoring DeleteServiceByID", logfields.ID, id)
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
func (s *serviceManagerAdapter) GetDeepCopyServiceByFrontend(frontend loadbalancer.L3n4Addr) (*loadbalancer.LegacySVC, bool) {
	// Used by pod watcher, which will be replaced when new implementation is enabled.
	return nil, false
}

// GetDeepCopyServiceByID implements service.ServiceManager.
func (s *serviceManagerAdapter) GetDeepCopyServiceByID(id loadbalancer.ServiceID) (*loadbalancer.LegacySVC, bool) {
	// Used by REST API
	return nil, false
}

// GetDeepCopyServices implements service.ServiceManager.
func (s *serviceManagerAdapter) GetDeepCopyServices() (svcs []*loadbalancer.LegacySVC) {
	// Used by REST API.
	txn := s.db.ReadTxn()
	for fe := range s.frontends.All(txn) {
		bes := []*loadbalancer.LegacyBackend{}
		svc := fe.Service
		for be := range fe.Backends {
			// Get the instance of the referenced service. This may be different from fe.ServiceName
			// if it is being redirected.
			beModel := &loadbalancer.LegacyBackend{
				FEPortName: "",
				ID:         0,
				Weight:     be.Weight,
				NodeName:   be.NodeName,
				ZoneID:     s.daemonConfig.GetZoneID(be.Zone),
				L3n4Addr:   be.Address,
				State:      be.State,
				Preferred:  true,
			}
			if len(be.PortNames) == 0 {
				bes = append(bes, beModel)
			} else {
				for _, portName := range be.PortNames {
					beModel = beModel.DeepCopy()
					beModel.FEPortName = portName
					bes = append(bes, beModel)
				}
			}
		}
		proxyPort := uint16(0)
		if svc.ProxyRedirect != nil {
			proxyPort = svc.ProxyRedirect.ProxyPort
		}

		svcType := fe.Type
		if fe.RedirectTo != nil {
			svcType = loadbalancer.SVCTypeLocalRedirect
		}

		svcModel := &loadbalancer.LegacySVC{
			Frontend: loadbalancer.L3n4AddrID{
				L3n4Addr: fe.Address,
				ID:       loadbalancer.ID(fe.ID),
			},
			Type:        svcType,
			Name:        fe.ServiceName,
			Annotations: fe.Service.Annotations,
			Backends:    bes,

			ForwardingMode:            "", // FIXME (not implemented)
			ExtTrafficPolicy:          svc.ExtTrafficPolicy,
			IntTrafficPolicy:          svc.IntTrafficPolicy,
			NatPolicy:                 svc.NatPolicy,
			SourceRangesPolicy:        "",                                  // FIXME (not implemented)
			ProxyDelegation:           loadbalancer.SVCProxyDelegationNone, // FIXME (not implemented)
			SessionAffinity:           svc.SessionAffinity,
			SessionAffinityTimeoutSec: uint32(svc.SessionAffinityTimeout),
			HealthCheckNodePort:       svc.HealthCheckNodePort,
			LoadBalancerAlgorithm:     svc.GetLBAlgorithmAnnotation(),
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
	if !localOnly {
		txn := s.writer.WriteTxn()
		s.initDone(txn)
		txn.Commit()
	}
	return
}

// TerminateUDPConnectionsToBackend implements service.ServiceManager.
func (s *serviceManagerAdapter) TerminateUDPConnectionsToBackend(l3n4Addr *loadbalancer.L3n4Addr) error {
	// Used by LRP, but not when new implementation is enabled.
	panic("unimplemented")
}

// UpdateBackendsState implements service.ServiceManager.
func (s *serviceManagerAdapter) UpdateBackendsState(backends []*loadbalancer.LegacyBackend) ([]loadbalancer.L3n4Addr, error) {
	// Used by REST API.
	s.log.Debug("serviceManagerAdapter: Ignoring UpdateBackendsState")
	return nil, nil
}

// UpsertService implements service.ServiceManager.
func (s *serviceManagerAdapter) UpsertService(svc *loadbalancer.LegacySVC) (bool, loadbalancer.ID, error) {
	// Used by pod watcher, LRP and REST API
	s.log.Debug("serviceManagerAdapter: Ignoring UpsertService", logfields.Name, svc.Name)
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

	fe, _, found := s.frontends.Get(txn, loadbalancer.FrontendByAddress(addr))
	if !found {
		return "", "", false
	}
	return fe.Service.Name.Namespace, fe.Service.Name.Name, true
}

var _ service.ServiceManager = &serviceManagerAdapter{}
