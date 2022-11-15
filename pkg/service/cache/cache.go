package cache

import (
	"context"
	"net"
	"sync"

	"github.com/cilium/cilium/pkg/hive"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/option"
	"github.com/sirupsen/logrus"
	corev1 "k8s.io/api/core/v1"

	datapathTypes "github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/k8s"
	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/stream"
)

// Temporary type aliases until the data types have been migrated
// somewhere sane.
type (
	Service        = k8s.Service
	ServiceEvent   = k8s.ServiceEvent
	ServiceID      = k8s.ServiceID
	Endpoints      = k8s.Endpoints
	EndpointSlices = k8s.EndpointSlices
)

// Services provides lookups of services the associated endpoints and
// an event stream for changes.
//
// The lookup methods will block until the services and endpoints have been
// synchronized and all subscribers have finished processing the events.
//
// The event stream does not provide a replay of events prior to subscription.
// If full history is required subscribe before start. The events are emitted
// synchronously, so a subscriber can process the event synchronously to block
// lookups prior to synchronization, e.g. to make sure GetServiceIP() only
// returns post-sync results that have already been applied to datapath.
//
// The event handlers must not call any of the Get* methods as they may block
// waiting for the synchronization.
type Services interface {
	stream.Observable[*ServiceEvent]

	GetServiceIP(svcID ServiceID) *loadbalancer.L3n4Addr
	GetServiceFrontendIP(svcID ServiceID, svcType loadbalancer.SVCType) net.IP
	GetEndpointsOfService(svcID ServiceID) *Endpoints
}

var Cell = cell.Module(
	"service-cache",
	"Service Cache stores services and associated endpoints",
	cell.Provide(newServiceCache),
)

type serviceCache struct {
	params serviceCacheParams

	ctx    context.Context // for stopping processLoop()
	cancel context.CancelFunc
	wg     sync.WaitGroup // for waiting for processLoop()

	// mu protects the services and endpoints maps
	mu lock.RWMutex

	services map[ServiceID]*Service

	// endpoints maps a service to a map of EndpointSlices. In case the cluster
	// is still using the v1.Endpoints, the key used in the internal map of
	// EndpointSlices is the v1.Endpoint name.
	endpoints map[ServiceID]*EndpointSlices

	// selfNodeZoneLabel implements the Kubernetes topology aware hints
	// by selecting only the backends in this node's zone.
	selfNodeZoneLabel string

	// synchronized is a wait group that is done when both services and endpoints
	// have been fully synchronized.
	synchronized sync.WaitGroup

	// TODO external endpoints

	src      stream.Observable[*ServiceEvent]
	emit     func(*ServiceEvent)
	complete func(error)
}

type serviceCacheParams struct {
	cell.In

	Lifecycle hive.Lifecycle
	Log       logrus.FieldLogger
	LocalNode resource.Resource[*corev1.Node]
	Services  resource.Resource[*slim_corev1.Service]
	Endpoints resource.Resource[*Endpoints]

	// FIXME: This should not be here.
	NodeAddressing datapathTypes.NodeAddressing
}

func newServiceCache(p serviceCacheParams) Services {
	sc := &serviceCache{
		params:    p,
		services:  map[ServiceID]*Service{},
		endpoints: map[ServiceID]*EndpointSlices{},
	}
	sc.ctx, sc.cancel = context.WithCancel(context.Background())
	sc.src, sc.emit, sc.complete = stream.Multicast[*ServiceEvent]()
	sc.synchronized.Add(3)
	p.Lifecycle.Append(sc)
	return sc
}

func (sc *serviceCache) Start(hive.HookContext) error {
	sc.wg.Add(1)
	go sc.processLoop()
	return nil
}

func (sc *serviceCache) Stop(hive.HookContext) error {
	sc.cancel()
	sc.wg.Wait()
	return nil
}

func (sc *serviceCache) processLoop() {
	defer sc.wg.Done()

	errs := make(chan error)
	defer close(errs)

	localNode := stream.ToChannel[resource.Event[*corev1.Node]](sc.ctx, errs, sc.params.LocalNode)
	services := stream.ToChannel[resource.Event[*slim_corev1.Service]](sc.ctx, errs, sc.params.Services)
	endpoints := stream.ToChannel[resource.Event[*Endpoints]](sc.ctx, errs, sc.params.Endpoints)

	for localNode != nil || services != nil || endpoints != nil {
		select {
		case ev, ok := <-localNode:
			if !ok {
				localNode = nil
			}
			ev.Handle(
				func() error {
					sc.synchronized.Done()
					return nil
				},
				sc.updateNode,
				nil,
			)
		case ev, ok := <-services:
			if !ok {
				services = nil
			}
			ev.Handle(
				func() error {
					sc.synchronized.Done()
					return nil
				},
				sc.updateService,
				sc.deleteService,
			)

		case ev, ok := <-endpoints:
			if !ok {
				endpoints = nil
			}
			ev.Handle(
				func() error {
					sc.synchronized.Done()
					return nil
				},
				sc.updateEndpoints,
				sc.deleteEndpoints,
			)
		}
	}

	// TODO log errors
}

func (sc *serviceCache) updateNode(key resource.Key, node *corev1.Node) error {
	// FIXME move this option into "ServicesConfig" or similar
	if !option.Config.EnableServiceTopology {
		return nil
	}

	sc.mu.Lock()
	defer sc.mu.Unlock()

	labels := node.GetLabels()
	zone := labels[k8s.LabelTopologyZone]

	if sc.selfNodeZoneLabel == zone {
		return nil
	}
	sc.selfNodeZoneLabel = zone

	// Since the node label changed, we need to re-emit the topology aware services
	// as their backends may have changed due to the new labels.
	for id, svc := range sc.services {
		if !svc.TopologyAware {
			continue
		}
		if endpoints, ready := sc.correlateEndpoints(id); ready {
			sc.emit(&ServiceEvent{
				Action:     k8s.UpdateService,
				ID:         id,
				Service:    svc,
				OldService: svc,
				Endpoints:  endpoints,
				SWG:        nil, // FIXME remove
			})
		}
	}
	return nil
}

func (sc *serviceCache) updateService(key resource.Key, k8sSvc *slim_corev1.Service) error {
	svcID, svc := k8s.ParseService(k8sSvc, sc.params.NodeAddressing)
	// TODO nil svc? what to do? do we want this retried? likely not.

	sc.mu.Lock()
	defer sc.mu.Unlock()

	oldService, ok := sc.services[svcID]
	if ok {
		if oldService.DeepEqual(svc) {
			return nil
		}
	}
	sc.services[svcID] = svc

	// Check if the corresponding Endpoints resource is already available, and
	// if so emit the service event.
	endpoints, serviceReady := sc.correlateEndpoints(svcID)
	if serviceReady {
		sc.emit(&ServiceEvent{
			Action:     k8s.UpdateService,
			ID:         svcID,
			Service:    svc,
			OldService: oldService,
			Endpoints:  endpoints,
			SWG:        nil, // FIXME SWG can be killed as emit() is synchronous.
		})
	}

	return nil
}

func (sc *serviceCache) deleteService(key resource.Key, svc *slim_corev1.Service) error {
	return nil
}

func (sc *serviceCache) updateEndpoints(key resource.Key, eps *Endpoints) error {
	return nil
}

func (sc *serviceCache) deleteEndpoints(key resource.Key, eps *Endpoints) error {
	return nil
}

func (sc *serviceCache) Observe(ctx context.Context, next func(*ServiceEvent), complete func(error)) {
	sc.src.Observe(ctx, next, complete)
}

func (sc *serviceCache) GetEndpointsOfService(svcID k8s.ServiceID) *k8s.Endpoints {
	sc.synchronized.Wait()
	panic("unimplemented")
}

func (sc *serviceCache) GetServiceFrontendIP(svcID k8s.ServiceID, svcType loadbalancer.SVCType) net.IP {
	sc.synchronized.Wait()
	panic("unimplemented")
}

func (sc *serviceCache) GetServiceIP(svcID k8s.ServiceID) *loadbalancer.L3n4Addr {
	sc.synchronized.Wait()
	panic("unimplemented")
}
