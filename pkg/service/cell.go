package service

import (
	"context"
	"errors"
	"net"
	"time"

	"github.com/cilium/workerpool"
	"github.com/sirupsen/logrus"

	"github.com/cilium/cilium/pkg/cidr"
	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/datapath"
	datapathTypes "github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/ip"
	"github.com/cilium/cilium/pkg/k8s"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/readiness"
	"github.com/cilium/cilium/pkg/service/cache"
	"github.com/cilium/cilium/pkg/service/config"
)

// TODO: Split the ServiceManager API into groups.
type ServiceManager interface {
	SetMonitorNotify(monitorNotify)
	SetEnvoyCache(envoyCache)

	// from redirectpolicymanager:
	DeleteService(frontend loadbalancer.L3n4Addr) (bool, error)
	UpsertService(*loadbalancer.SVC) (bool, loadbalancer.ID, error)

	// from k8s watcher. used in cilium_envoy_config.go and pod.go.
	RegisterL7LBService(serviceName, resourceName loadbalancer.ServiceName, ports []string, proxyPort uint16) error
	RegisterL7LBServiceBackendSync(serviceName, resourceName loadbalancer.ServiceName, ports []string) error
	RemoveL7LBService(serviceName, resourceName loadbalancer.ServiceName) error

	// from daemon.go
	RestoreServices() error
	SyncServicesOnDeviceChange(datapathTypes.NodeAddressing)

	// from daemon/cmd/loadbalancer.go
	UpdateBackendsState([]*loadbalancer.Backend) error
	DeleteServiceByID(loadbalancer.ServiceID) (bool, error)
	GetDeepCopyServiceByID(loadbalancer.ServiceID) (*loadbalancer.SVC, bool)
	GetDeepCopyServices() []*loadbalancer.SVC

	// from daemon/cmd/datapath.go
	InitMaps(ipv6, ipv4 bool, sockRevNat bool, restoreState bool) error

	// from daemon/cmd/hubble.go
	GetServiceNameByAddr(loadbalancer.L3n4Addr) (ns, name string, ok bool)

	// from daemon/cmd/state.go
	SyncWithK8sFinished() error

	// from daemon/cmd/kube_proxy_healthz.go.
	GetLastUpdatedTs() time.Time
	GetCurrentTs() time.Time
}

const (
	moduleId = "service-manager"
)

var Cell = cell.Module(
	moduleId,
	"Service Manager",

	cell.Provide(newServiceManager),
)

type serviceManagerParams struct {
	cell.In

	Lifecycle    hive.Lifecycle
	Config       config.ServiceConfig
	ServiceCache cache.ServiceCache
	Datapath     datapath.Datapath
	Readiness    *readiness.Readiness
}

func newServiceManager(p serviceManagerParams) ServiceManager {
	svc := newService(
		p.Config,
		nil,
		nil,
		p.Datapath.LBMap(),
	)
	sm := &serviceManager{
		serviceManagerParams: p,
		Service:              svc,
		wp:                   workerpool.New(8),
	}
	p.Lifecycle.Append(sm)
	sm.ready = p.Readiness.Add(moduleId)
	return sm
}

// TODO: this currently just wraps '*Service' and throws on top the k8s event
// handling. Reimplement the event handling as "K8sServicesHandler" or some such
// and put the rest back into '*Service' (and rename it).
type serviceManager struct {
	serviceManagerParams
	*Service

	wp    *workerpool.WorkerPool
	ready func()
}

var _ ServiceManager = &serviceManager{}
var _ hive.HookInterface = &serviceManager{}

// Start implements hive.HookInterface
func (sm *serviceManager) Start(hive.HookContext) error {
	return sm.wp.Submit("processEvents", sm.processEvents)
}

// Stop implements hive.HookInterface
func (sm *serviceManager) Stop(hive.HookContext) error {
	return sm.wp.Close()
}

// TODO: Check whether delayed assignment of these screws things up.
func (sm *serviceManager) SetMonitorNotify(m monitorNotify) {
	sm.Lock()
	sm.monitorNotify = m
	sm.Unlock()
}

func (sm *serviceManager) SetEnvoyCache(e envoyCache) {
	sm.Lock()
	sm.envoyCache = e
	sm.Unlock()
}

func (sm *serviceManager) processEvents(ctx context.Context) error {
	log.Info("serviceManager: Starting to process events!")
	for event := range sm.ServiceCache.Events(ctx) {
		switch event.Action {
		case cache.Synchronized:
			log.Info("serviceManager: Synchronized!")
		case cache.UpdateService:
			sm.upsert(event.ID, event.OldService, event.Service, event.Endpoints)
		case cache.DeleteService:
			sm.delete(event.ID, event.Service, event.Endpoints)
		}
	}
	log.Info("serviceManager: processEvents terminated")
	return nil
}

//
// Delicious copy-pasta from watcher.go follows:
//

func (sm *serviceManager) upsert(svcID k8s.ServiceID, oldSvc, svc *k8s.Service, endpoints *k8s.Endpoints) error {
	log.Infof("serviceManager.upsert(%s)", svcID)

	// Headless services do not need any datapath implementation
	if svc.IsHeadless {
		return nil
	}

	scopedLog := log.WithFields(logrus.Fields{
		logfields.K8sSvcName:   svcID.Name,
		logfields.K8sNamespace: svcID.Namespace,
	})

	svcs := datapathSVCs(svc, endpoints)
	svcMap := hashSVCMap(svcs)

	if oldSvc != nil {
		// If we have oldService then we need to detect which frontends
		// are no longer in the updated service and delete them in the datapath.

		oldSVCs := datapathSVCs(oldSvc, endpoints)
		oldSVCMap := hashSVCMap(oldSVCs)

		for svcHash, oldSvc := range oldSVCMap {
			if _, ok := svcMap[svcHash]; !ok {
				if found, err := sm.DeleteService(oldSvc); err != nil {
					scopedLog.WithError(err).WithField(logfields.Object, logfields.Repr(oldSvc)).
						Warn("Error deleting service by frontend")
				} else if !found {
					scopedLog.WithField(logfields.Object, logfields.Repr(oldSvc)).Warn("service not found")
				} else {
					scopedLog.Debugf("# cilium lb delete-service %s %d 0", oldSvc.AddrCluster.String(), oldSvc.Port)
				}
			}
		}
	}

	for _, dpSvc := range svcs {
		p := &loadbalancer.SVC{
			Frontend:                  dpSvc.Frontend,
			Backends:                  dpSvc.Backends,
			Type:                      dpSvc.Type,
			TrafficPolicy:             dpSvc.TrafficPolicy,
			SessionAffinity:           dpSvc.SessionAffinity,
			SessionAffinityTimeoutSec: dpSvc.SessionAffinityTimeoutSec,
			HealthCheckNodePort:       dpSvc.HealthCheckNodePort,
			LoadBalancerSourceRanges:  dpSvc.LoadBalancerSourceRanges,
			Name: loadbalancer.ServiceName{
				Name:      svcID.Name,
				Namespace: svcID.Namespace,
			},
		}
		if _, _, err := sm.UpsertService(p); err != nil {
			if errors.Is(err, NewErrLocalRedirectServiceExists(p.Frontend, p.Name)) {
				scopedLog.WithError(err).Debug("Error while inserting service in LB map")
			} else {
				scopedLog.WithError(err).Error("Error while inserting service in LB map")
			}
		}
	}
	return nil
}

func (sm *serviceManager) delete(svc k8s.ServiceID, svcInfo *k8s.Service, se *k8s.Endpoints) error {
	// Headless services do not need any datapath implementation
	if svcInfo.IsHeadless {
		return nil
	}

	scopedLog := log.WithFields(logrus.Fields{
		logfields.K8sSvcName:   svc.Name,
		logfields.K8sNamespace: svc.Namespace,
	})

	repPorts := svcInfo.UniquePorts()

	frontends := []*loadbalancer.L3n4Addr{}

	for portName, svcPort := range svcInfo.Ports {
		if !repPorts[svcPort.Port] {
			continue
		}
		repPorts[svcPort.Port] = false

		for _, feIP := range svcInfo.FrontendIPs {
			fe := loadbalancer.NewL3n4Addr(svcPort.Protocol, cmtypes.MustAddrClusterFromIP(feIP), svcPort.Port, loadbalancer.ScopeExternal)
			frontends = append(frontends, fe)
		}

		for _, nodePortFE := range svcInfo.NodePorts[portName] {
			frontends = append(frontends, &nodePortFE.L3n4Addr)
			if svcInfo.TrafficPolicy == loadbalancer.SVCTrafficPolicyLocal {
				cpFE := nodePortFE.L3n4Addr.DeepCopy()
				cpFE.Scope = loadbalancer.ScopeInternal
				frontends = append(frontends, cpFE)
			}
		}

		for _, k8sExternalIP := range svcInfo.K8sExternalIPs {
			frontends = append(frontends, loadbalancer.NewL3n4Addr(svcPort.Protocol, cmtypes.MustAddrClusterFromIP(k8sExternalIP), svcPort.Port, loadbalancer.ScopeExternal))
		}

		for _, ip := range svcInfo.LoadBalancerIPs {
			addrCluster := cmtypes.MustAddrClusterFromIP(ip)
			frontends = append(frontends, loadbalancer.NewL3n4Addr(svcPort.Protocol, addrCluster, svcPort.Port, loadbalancer.ScopeExternal))
			if svcInfo.TrafficPolicy == loadbalancer.SVCTrafficPolicyLocal {
				frontends = append(frontends, loadbalancer.NewL3n4Addr(svcPort.Protocol, addrCluster, svcPort.Port, loadbalancer.ScopeInternal))
			}
		}
	}

	for _, fe := range frontends {
		if found, err := sm.DeleteService(*fe); err != nil {
			scopedLog.WithError(err).WithField(logfields.Object, logfields.Repr(fe)).
				Warn("Error deleting service by frontend")
		} else if !found {
			scopedLog.WithField(logfields.Object, logfields.Repr(fe)).Warn("service not found")
		} else {
			scopedLog.Debugf("# cilium lb delete-service %s %d 0", fe.AddrCluster.String(), fe.Port)
		}
	}
	return nil
}

// HashSVCMap returns a mapping of all frontend's hash to the its corresponded
// value.
func hashSVCMap(svcs []loadbalancer.SVC) map[string]loadbalancer.L3n4Addr {
	m := map[string]loadbalancer.L3n4Addr{}
	for _, svc := range svcs {
		m[svc.Frontend.L3n4Addr.Hash()] = svc.Frontend.L3n4Addr
	}
	return m
}

// datapathSVCs returns all services that should be set in the datapath.
func datapathSVCs(svc *k8s.Service, endpoints *k8s.Endpoints) (svcs []loadbalancer.SVC) {
	uniqPorts := svc.UniquePorts()

	clusterIPPorts := map[loadbalancer.FEPortName]*loadbalancer.L4Addr{}
	for fePortName, fePort := range svc.Ports {
		if !uniqPorts[fePort.Port] {
			continue
		}
		uniqPorts[fePort.Port] = false
		clusterIPPorts[fePortName] = fePort
	}

	for _, frontendIP := range svc.FrontendIPs {
		dpSVC := genCartesianProduct(frontendIP, svc.TrafficPolicy, loadbalancer.SVCTypeClusterIP, clusterIPPorts, endpoints)
		svcs = append(svcs, dpSVC...)
	}

	for _, ip := range svc.LoadBalancerIPs {
		dpSVC := genCartesianProduct(ip, svc.TrafficPolicy, loadbalancer.SVCTypeLoadBalancer, clusterIPPorts, endpoints)
		svcs = append(svcs, dpSVC...)
	}

	for _, k8sExternalIP := range svc.K8sExternalIPs {
		dpSVC := genCartesianProduct(k8sExternalIP, svc.TrafficPolicy, loadbalancer.SVCTypeExternalIPs, clusterIPPorts, endpoints)
		svcs = append(svcs, dpSVC...)
	}

	for fePortName := range clusterIPPorts {
		for _, nodePortFE := range svc.NodePorts[fePortName] {
			nodePortPorts := map[loadbalancer.FEPortName]*loadbalancer.L4Addr{
				fePortName: &nodePortFE.L4Addr,
			}
			dpSVC := genCartesianProduct(nodePortFE.AddrCluster.Addr().AsSlice(), svc.TrafficPolicy, loadbalancer.SVCTypeNodePort, nodePortPorts, endpoints)
			svcs = append(svcs, dpSVC...)
		}
	}

	lbSrcRanges := make([]*cidr.CIDR, 0, len(svc.LoadBalancerSourceRanges))
	for _, cidr := range svc.LoadBalancerSourceRanges {
		lbSrcRanges = append(lbSrcRanges, cidr)
	}

	// apply common service properties
	for i := range svcs {
		svcs[i].TrafficPolicy = svc.TrafficPolicy
		svcs[i].HealthCheckNodePort = svc.HealthCheckNodePort
		svcs[i].SessionAffinity = svc.SessionAffinity
		svcs[i].SessionAffinityTimeoutSec = svc.SessionAffinityTimeoutSec
		if svcs[i].Type == loadbalancer.SVCTypeLoadBalancer {
			svcs[i].LoadBalancerSourceRanges = lbSrcRanges
		}
	}

	return svcs
}

func genCartesianProduct(
	fe net.IP,
	svcTrafficPolicy loadbalancer.SVCTrafficPolicy,
	svcType loadbalancer.SVCType,
	ports map[loadbalancer.FEPortName]*loadbalancer.L4Addr,
	bes *k8s.Endpoints,
) []loadbalancer.SVC {
	var svcSize int

	// For externalTrafficPolicy=Local we add both external and internal
	// scoped frontends, hence twice the size for only this case.
	if svcTrafficPolicy == loadbalancer.SVCTrafficPolicyLocal &&
		(svcType == loadbalancer.SVCTypeLoadBalancer || svcType == loadbalancer.SVCTypeNodePort) {
		svcSize = len(ports) * 2
	} else {
		svcSize = len(ports)
	}

	svcs := make([]loadbalancer.SVC, 0, svcSize)
	feFamilyIPv6 := ip.IsIPv6(fe)

	for fePortName, fePort := range ports {
		var besValues []*loadbalancer.Backend
		for addrCluster, backend := range bes.Backends {
			if backendPort := backend.Ports[string(fePortName)]; backendPort != nil && feFamilyIPv6 == addrCluster.Is6() {
				backendState := loadbalancer.BackendStateActive
				if backend.Terminating {
					backendState = loadbalancer.BackendStateTerminating
				}
				besValues = append(besValues, &loadbalancer.Backend{
					FEPortName: string(fePortName),
					NodeName:   backend.NodeName,
					L3n4Addr: loadbalancer.L3n4Addr{
						AddrCluster: addrCluster,
						L4Addr:      *backendPort,
					},
					State:     backendState,
					Preferred: loadbalancer.Preferred(backend.Preferred),
					Weight:    loadbalancer.DefaultBackendWeight,
				})
			}
		}

		addrCluster := cmtypes.MustAddrClusterFromIP(fe)

		// External scoped entry.
		svcs = append(svcs,
			loadbalancer.SVC{
				Frontend: loadbalancer.L3n4AddrID{
					L3n4Addr: loadbalancer.L3n4Addr{
						AddrCluster: addrCluster,
						L4Addr: loadbalancer.L4Addr{
							Protocol: fePort.Protocol,
							Port:     fePort.Port,
						},
						Scope: loadbalancer.ScopeExternal,
					},
					ID: loadbalancer.ID(0),
				},
				Backends: besValues,
				Type:     svcType,
			})

		// Internal scoped entry only for Local traffic policy.
		if svcSize > len(ports) {
			svcs = append(svcs,
				loadbalancer.SVC{
					Frontend: loadbalancer.L3n4AddrID{
						L3n4Addr: loadbalancer.L3n4Addr{
							AddrCluster: addrCluster,
							L4Addr: loadbalancer.L4Addr{
								Protocol: fePort.Protocol,
								Port:     fePort.Port,
							},
							Scope: loadbalancer.ScopeInternal,
						},
						ID: loadbalancer.ID(0),
					},
					Backends: besValues,
					Type:     svcType,
				})
		}
	}
	return svcs
}
