package servicemanager

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync"

	"github.com/cilium/cilium/pkg/cidr"
	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/ip"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/service/config"
	"github.com/cilium/workerpool"
	"github.com/sirupsen/logrus"
	corev1 "k8s.io/api/core/v1"

	datapathTypes "github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/k8s"
	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/stream"
)

type serviceCache struct {
	serviceCacheParams

	// serviceCacheState is the mutable state associated with the service cache.
	// It is separated into its own struct for debug dumping purposes.
	serviceCacheState

	// mcast is the set of primitives for multicasting future service events
	// to subscribers.
	mcast struct {
		src      stream.Observable[*ServiceEvent]
		emit     func(*ServiceEvent)
		complete func(error)
	}

	// mu protects the service cache state
	mu lock.RWMutex

	// wp is the worker pool for background workers.
	wp *workerpool.WorkerPool

	// syncChan is closed when all resources have synchronized and all
	// subscribers have received all events prior to the synchronized event.
	syncChan chan struct{}

	// subChan receives the new subscribers from Events(). This allows sequential handling of
	// all events and thus makes it easier to reason about feeding new subscribers
	// the current state.
	subChan chan *newSub
}

var _ ServiceCache = &serviceCache{}
var _ k8s.ServiceIPGetter = &serviceCache{}

type serviceCacheParams struct {
	cell.In

	Config    config.ServiceConfig
	Lifecycle hive.Lifecycle
	Log       logrus.FieldLogger
	LocalNode resource.Resource[*corev1.Node]
	Services  resource.Resource[*slim_corev1.Service]
	Endpoints resource.Resource[*Endpoints]

	// FIXME: This should not be here. It's used by k8s.ParseService() to expand
	// the nodeport frontends. That should be performed by datapath.
	NodeAddressing datapathTypes.NodeAddressing `optional:"true"`
}

const (
	// maxWorkers is the limit for concurrent background work. In addition to processEvents() service
	// cache has a temporary worker in Events() to feed the subscriber the initial
	// events.
	maxWorkers = 8
)

func newServiceCache(p serviceCacheParams) ServiceCache {
	sc := &serviceCache{
		serviceCacheParams: p,
		serviceCacheState: serviceCacheState{
			services:          map[ServiceID]*Service{},
			endpoints:         map[ServiceID]*EndpointSlices{},
			externalEndpoints: map[ServiceID]externalEndpoints{},
		},
		syncChan: make(chan struct{}),
		subChan:  make(chan *newSub),
	}
	sc.mcast.src, sc.mcast.emit, sc.mcast.complete = stream.Multicast[*ServiceEvent]()
	sc.wp = workerpool.New(maxWorkers)
	p.Lifecycle.Append(sc)

	return sc
}

func (sc *serviceCache) Start(hive.HookContext) error {
	return sc.wp.Submit("processK8sEvents", sc.processK8sEvents)
}

func (sc *serviceCache) Stop(hive.HookContext) error {
	return sc.wp.Close()
}

type newSub struct {
	ctx    context.Context
	events chan *ServiceEvent
}

func (sc *serviceCache) processK8sEvents(ctx context.Context) error {
	var numSync int // Number of resources waiting to be synchronized.

	nodes := sc.LocalNode.Events(ctx)
	numSync++
	defer drain(nodes)

	services := sc.Services.Events(ctx)
	numSync++
	defer drain(services)

	endpoints := sc.Endpoints.Events(ctx)
	numSync++
	defer drain(endpoints)

	for {
		select {
		case <-ctx.Done():
			return nil

		case newSub := <-sc.subChan:
			sc.subscribe(ctx, newSub)

		case ev := <-nodes:
			switch ev.Kind {
			case resource.Sync:
				sc.Log.Info("Nodes synced")
				numSync--
			case resource.Upsert:
				sc.updateNode(ev.Key, ev.Object)
			}
			ev.Done(nil)

		case ev := <-services:
			switch ev.Kind {
			case resource.Sync:
				sc.Log.Info("Services synced")
				numSync--
			case resource.Upsert:
				sc.updateService(ev.Key, ev.Object)
			case resource.Delete:
				sc.deleteService(ev.Key, ev.Object)
			}
			ev.Done(nil)

		case ev := <-endpoints:
			switch ev.Kind {
			case resource.Sync:
				sc.Log.Info("Endpoints synced")
				numSync--
			case resource.Upsert:
				sc.updateEndpoints(ev.Key, ev.Object)
			case resource.Delete:
				sc.deleteEndpoints(ev.Key, ev.Object)
			}
			ev.Done(nil)
		}

		if numSync == 0 {
			sc.Log.Info("Emitting sync!")
			numSync = -1 // in order to handle this only once.
			sc.mcast.emit(&ServiceEvent{Action: Synchronized})
			close(sc.syncChan)
			sc.Log.Info("Done with emitting sync")
		}
	}
}

func (sc *serviceCache) subscribe(workerCtx context.Context, sub *newSub) {
	sc.mu.RLock()
	defer sc.mu.RUnlock()

	// Emit the current set of ready services. A slow subscriber will
	// block others, but this is acceptable as the assumption is that
	// there are only a few subscribers and they subscribe early.
	for id, svc := range sc.services {
		if endpoints, ready := sc.correlateEndpoints(id); ready {
			event := &ServiceEvent{
				Action:     UpdateService,
				ID:         id,
				Service:    svc,
				OldService: svc,
				Endpoints:  endpoints,
			}
			select {
			case <-sub.ctx.Done(): // subscriber cancelled
				close(sub.events)
				return
			case <-workerCtx.Done(): // worker cancelled
				close(sub.events)
				return
			case sub.events <- event:
			}
		}
	}

	// Subscribe to new events.
	sc.mcast.src.Observe(
		sub.ctx,
		func(ev *ServiceEvent) { sub.events <- ev },
		func(error) { close(sub.events) },
	)

	// Check if we're already synchronized by checking if syncChan has closed.
	select {
	case <-sc.syncChan:
		sc.Log.Info("sub: Already synced, emitting it")
		sub.events <- &ServiceEvent{Action: Synchronized}
		sc.Log.Info("sub: Sync emit done")
	default:
		sc.Log.Info("sub: Not synced yet!")
		// Not synchronized yet, the event will be emitted by later when
		// all resources have synchronized.
	}

}

func (sc *serviceCache) updateNode(key resource.Key, node *corev1.Node) {
	if !sc.Config.EnableServiceTopology {
		return
	}

	sc.mu.Lock()
	defer sc.mu.Unlock()

	labels := node.GetLabels()
	zone := labels[LabelTopologyZone]

	if sc.selfNodeZoneLabel == zone {
		return
	}
	sc.selfNodeZoneLabel = zone

	// Since the node label changed, we need to re-emit the topology aware services
	// as their backends may have changed due to the new labels.
	for id, svc := range sc.services {
		if !svc.TopologyAware {
			continue
		}
		if endpoints, ready := sc.correlateEndpoints(id); ready {
			sc.mcast.emit(&ServiceEvent{
				Action:     UpdateService,
				ID:         id,
				Service:    svc,
				OldService: svc,
				Endpoints:  endpoints,
			})
		}
	}
	return
}

func (sc *serviceCache) updateService(key resource.Key, k8sSvc *slim_corev1.Service) {
	// FIXME move ParseService and the Service type into pkg/service/types or similar from
	// pkg/k8s.
	svcID, svc := k8s.ParseService(k8sSvc, sc.NodeAddressing)
	if svc == nil {
		// Retrying doesn't make sense here, since we'd just get back the
		// same object. The problem would be with our parsing code, so log
		// the error so we can fix the parsing.
		sc.Log.Errorf("Failed to parse service object %s", key)
		return
	}

	sc.Log.Infof("updateService: svcID=%s, svc=%#v", svcID, svc)

	sc.mu.Lock()
	defer sc.mu.Unlock()

	oldService, ok := sc.services[svcID]
	if ok {
		if oldService.DeepEqual(svc) {
			return
		}
	}
	sc.services[svcID] = svc

	// Check if the corresponding Endpoints resource is already available, and
	// if so emit the service event.
	endpoints, serviceReady := sc.correlateEndpoints(svcID)
	if serviceReady {
		sc.mcast.emit(&ServiceEvent{
			Action:     UpdateService,
			ID:         svcID,
			Service:    svc,
			OldService: oldService,
			Endpoints:  endpoints,
		})
	}
}

func (sc *serviceCache) deleteService(key resource.Key, svc *slim_corev1.Service) {
	svcID := k8s.ParseServiceID(svc)

	sc.mu.Lock()
	defer sc.mu.Unlock()

	oldService, serviceOK := sc.services[svcID]
	endpoints, _ := sc.correlateEndpoints(svcID)
	delete(sc.services, svcID)

	if serviceOK {
		sc.mcast.emit(&ServiceEvent{
			Action:    DeleteService,
			ID:        svcID,
			Service:   oldService,
			Endpoints: endpoints,
		})
	}
}

func newEndpointSlices() *EndpointSlices {
	return &EndpointSlices{
		EpSlices: map[string]*Endpoints{},
	}
}

func (sc *serviceCache) updateEndpoints(key resource.Key, newEps *Endpoints) {
	sc.mu.Lock()
	defer sc.mu.Unlock()

	esName := newEps.EndpointSliceID.EndpointSliceName
	svcID := newEps.EndpointSliceID.ServiceID

	sc.Log.Infof("updateEndpoints(%s): svcID=%s, esName=%s",
		key, svcID, esName)

	eps, ok := sc.endpoints[svcID]
	if ok {
		if eps.EpSlices[esName].DeepEqual(newEps) {
			return
		}
	} else {
		eps = newEndpointSlices()
		sc.endpoints[svcID] = eps
	}
	eps.Upsert(esName, newEps)

	// Check if the corresponding Endpoints resource is already available
	svc, ok := sc.services[svcID]
	endpoints, serviceReady := sc.correlateEndpoints(svcID)
	if ok && serviceReady {
		sc.mcast.emit(&ServiceEvent{
			Action:    UpdateService,
			ID:        svcID,
			Service:   svc,
			Endpoints: endpoints,
		})
	}
	return
}

func (sc *serviceCache) deleteEndpoints(key resource.Key, eps *Endpoints) {
	sc.mu.Lock()
	defer sc.mu.Unlock()

	esName := eps.EndpointSliceID.EndpointSliceName
	svcID := eps.EndpointSliceID.ServiceID

	svc, serviceOK := sc.services[svcID]
	isEmpty := sc.endpoints[svcID].Delete(esName)
	if isEmpty {
		delete(sc.endpoints, svcID)
	}
	endpoints, _ := sc.correlateEndpoints(svcID)

	if serviceOK {
		sc.mcast.emit(&ServiceEvent{
			Action:    UpdateService,
			ID:        svcID,
			Service:   svc,
			Endpoints: endpoints,
		})
	}
}

func drain[T any](ch <-chan T) {
	for range ch {
	}
}


var K8sHandlerCell = cell.Module(
	"service-k8s-handler",
	"Manages services from Kubernetes",

	cell.Provide(newK8sHandler),
	cell.Invoke(func(*k8sHandler){}),
)

type k8sHandlerParams struct {
	cell.In

	ServiceManager ServiceManager

	Log       logrus.FieldLogger
	LocalNode resource.Resource[*corev1.Node]
	Services  resource.Resource[*slim_corev1.Service]
	Endpoints resource.Resource[*k8s.Endpoints]

}

type serviceEntry struct {
	svc *k8s.Service

	eps map[string]*k8s.Endpoints

	frontends []*Frontend
	backends []*Backend
}

type k8sHandler struct {
	k8sHandlerParams

	handle ServiceHandle

	entries map[resource.Key]*serviceEntry
}

func newK8sHandler(lc hive.Lifecycle, p k8sHandlerParams) *k8sHandler {
	handler := &k8sHandler{
		k8sHandlerParams: p,
		handle: p.ServiceManager.NewHandle("k8s-handler"),
	}

	var wg sync.WaitGroup
	ctx, cancel := context.WithCancel(context.Background())

	lc.Append(
		hive.Hook{
			OnStart: func(hive.HookContext) error {
				wg.Add(1)
				go handler.processLoop(ctx)
				return nil
			},
			OnStop: func(hive.HookContext) error {
				cancel()
				wg.Wait()
				return nil
			},
		})

	return handler
}

func (k *k8sHandler) processLoop(ctx context.Context) error {
	var numSync int // Number of resources waiting to be synchronized.

	/*
	nodes := p.LocalNode.Events(ctx)
	numSync++
	defer drain(nodes)*/

	services := k.Services.Events(ctx)
	numSync++
	defer drain(services)

	endpoints := k.Endpoints.Events(ctx)
	numSync++
	defer drain(endpoints)

	for {
		select {
		case <-ctx.Done():
			return nil

		/*
		case ev := <-nodes:
			switch ev.Kind {
			case resource.Sync:
				numSync--
			case resource.Upsert:
				sc.updateNode(ev.Key, ev.Object)
			}
			ev.Done(nil)*/

		case ev := <-services:
			switch ev.Kind {
			case resource.Sync:
				numSync--
			case resource.Upsert:
				k.updateService(ev.Key, ev.Object)
			case resource.Delete:
				k.deleteService(ev.Key, ev.Object)
			}
			ev.Done(nil)

		case ev := <-endpoints:
			switch ev.Kind {
			case resource.Sync:
				numSync--
			case resource.Upsert:
				k.updateEndpoints(ev.Key, ev.Object)
			case resource.Delete:
				k.deleteEndpoints(ev.Key, ev.Object)
			}
			ev.Done(nil)
		}

		if numSync == 0 {
			numSync = -1 // in order to handle this only once.
			// TODO
		}
	}
}

func (k *k8sHandler) updateService(key resource.Key, svc*slim_corev1.Service) {
	if strings.ToLower(svc.Spec.ClusterIP) == "none" {
		// Headless services are ignored.
		return
	}

	frontends, err := serviceToFrontends(k8sSvc)

}

func (k *k8sHandler) deleteService(key resource.Key, k8sSvc *slim_corev1.Service) {
}

func (k *k8sHandler) updateEndpoints(key resource.Key, eps *k8s.Endpoints) {
}
func (k *k8sHandler) deleteEndpoints(key resource.Key, eps *k8s.Endpoints) {
}

// parseService parses the k8s Service object into individual load-balancer service.
func serviceToFrontends(svc *slim_corev1.Service) ([]*Frontend, error) {
	// Since the frontends share a lot of fields, parse the service
	// into a base prototype object.
	base, err := parseBaseFrontend(svc)
	if err != nil {
		// TODO: How do we report parse/validation errors towards the
		// operator?
		return nil, err
	}

	builder := frontendsBuilder{base: base, svc: svc}

	{
		clusterIPs := svc.Spec.ClusterIPs
		if len(clusterIPs) == 0 {
			clusterIPs = []string{svc.Spec.ClusterIP}
		}
		builder.append(loadbalancer.SVCTypeClusterIP, clusterIPs)
	}

	builder.append(loadbalancer.SVCTypeExternalIPs, svc.Spec.ExternalIPs)

	{
		loadBalancerIPs := []string{}
		for _, ip := range svc.Status.LoadBalancer.Ingress {
			if ip.IP != "" {
				loadBalancerIPs = append(loadBalancerIPs, ip.IP)
			}
		}
		builder.append(loadbalancer.SVCTypeLoadBalancer, loadBalancerIPs)
	}

	if svc.Spec.Type == slim_corev1.ServiceTypeNodePort {
		builder.appendNodePort()
	}

	return builder.list, nil
}

type frontendsBuilder struct {
	base Frontend
	svc *slim_corev1.Service

	list []*Frontend
}

func (b *frontendsBuilder) appendNodePort() {
	// NodePort is special as the frontends are all addresses of the
	// local node and thus an implementation detail of datapath.
	for _, port := range b.svc.Spec.Ports {
		l4 := loadbalancer.L4Addr{loadbalancer.L4Type(port.Protocol), uint16(port.Port)}
		fe := b.base
		fe.Address = loadbalancer.L3n4Addr{
			/* AddrCluster not relevant for NodePort */
			L4Addr:      l4,
			Scope:       loadbalancer.ScopeExternal,
		}
		fe.Type = loadbalancer.SVCTypeNodePort
		b.list = append(b.list, &fe)
	}
}

func (b *frontendsBuilder) append(typ loadbalancer.SVCType, ips []string) {
	for _, ipstr := range ips {
		addr, err := cmtypes.ParseAddrCluster(ipstr)
		if err != nil {
			// FIXME handle bad ips? not done by original code
			continue
		}

		for _, port := range b.svc.Spec.Ports {
			l4 := loadbalancer.L4Addr{loadbalancer.L4Type(port.Protocol), uint16(port.Port)}
			fe := b.base
			fe.Address = loadbalancer.L3n4Addr{
				AddrCluster: addr,
				L4Addr:      l4,
				Scope:       loadbalancer.ScopeExternal,
			}
			fe.Type = typ
			b.list = append(b.list, &fe)
		}
	}
}

func parseBaseFrontend(svc *slim_corev1.Service) (Frontend, error) {
	base := Frontend{}
	base.Type = loadbalancer.SVCTypeNone

	switch svc.Spec.ExternalTrafficPolicy {
	case slim_corev1.ServiceExternalTrafficPolicyTypeLocal:
		base.TrafficPolicy = loadbalancer.SVCTrafficPolicyLocal
	default:
		base.TrafficPolicy = loadbalancer.SVCTrafficPolicyCluster
	}
	panic("TBD")


}

/*
func processK8sEvents(h ServiceHandle, ctx context.Context, sc cache.ServiceCache, wg *sync.WaitGroup) {
	defer wg.Done()
	log.Info("processK8sEvents: Starting to process events!")
	for event := range sc.Events(ctx) {
		switch event.Action {
		case cache.Synchronized:
			log.Info("serviceHandle: Synchronized!")
			h.Synchronized()
		case cache.UpdateService:
			upsertK8s(h, event.ID, event.OldService, event.Service, event.Endpoints)
		case cache.DeleteService:
			deleteK8s(h, event.ID, event.Service, event.Endpoints)
		}
	}
	log.Info("processK8sEvents: terminated")
}*/

//
// Delicious copy-pasta from watcher.go follows:
//

func upsertK8s(h ServiceHandle, svcID k8s.ServiceID, oldSvc, svc *k8s.Service, endpoints *k8s.Endpoints) error {
	log.Infof("serviceManager.upsert(%s), endpoints: %v", svcID, endpoints.Backends)

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
				if found, err := h.DeleteService(oldSvc); err != nil {
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
		log.Infof("h.UpsertService: %#v", p)
		if _, _, err := h.UpsertService(p); err != nil {
			if errors.Is(err, NewErrLocalRedirectServiceExists(p.Frontend, p.Name)) {
				scopedLog.WithError(err).Debug("Error while inserting service in LB map")
			} else {
				scopedLog.WithError(err).Error("Error while inserting service in LB map")
			}
		}
	}
	return nil
}

func deleteK8s(h ServiceHandle, svc k8s.ServiceID, svcInfo *k8s.Service, se *k8s.Endpoints) error {
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
		if found, err := h.DeleteService(*fe); err != nil {
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
