package cache

import (
	"context"
	"net"

	"github.com/cilium/cilium/pkg/clustermesh"
	"github.com/cilium/cilium/pkg/hive"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/service/config"
	"github.com/cilium/cilium/pkg/service/store"
	"github.com/cilium/workerpool"
	"github.com/davecgh/go-spew/spew"
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
	ServiceID      = k8s.ServiceID
	Endpoints      = k8s.Endpoints
	EndpointSlices = k8s.EndpointSlices
)

// ServiceLookup provides lookups of services the associated endpoints and
// an event stream for changes.
type ServiceLookup interface {
	// Events returns an unbuffered channel of service events. When context is canceled
	// the channel is closed. Subscriber must drain the channel after cancelling to avoid
	// blocking other subscribers.
	//
	// The channel is unbuffered to make sure subscribers can block sc.syncChan from
	// being marked done before they have processed all events prior to the sync event.
	Events(context.Context) <-chan *ServiceEvent

	// TODO: Kill these and instead only expose the Events stream? GetServiceIP is needed
	// by the kvstore dialer. Consider writing a lightweight utility that uses Resource[Service]
	// and Resource[Endpoints] instead? One complication is with whether or not we should try
	// and avoid waiting for synchronization before dialing...  
	GetEndpointsOfService(svcID ServiceID) *Endpoints
	GetServiceAddrsWithType(svcID k8s.ServiceID, svcType loadbalancer.SVCType) (map[loadbalancer.FEPortName][]*loadbalancer.L3n4Addr, int)
	GetServiceFrontendIP(svcID ServiceID, svcType loadbalancer.SVCType) net.IP
	GetServiceIP(svcID ServiceID) *loadbalancer.L3n4Addr

	// WaitForSync blocks until services have been synchronized and all subscribers to events
	// have processed up to sync event. Blocking can be canceled by canceling the provided context.
	// Context is optional. Returns true if synchronized, false if context canceled.
	//
	// TODO: Likely we don't want this. It's a replacement for StoppableWaitGroup in the "cache sync"
	// entries of services and endpoints. What we really want is ServiceManager to tell when it's ready. In
	// general I think we want to wait for readiness from modules directly rather than wiring
	// indirect mechanisms through the whole pipeline. E.g. "startCNIConfWriter depends on an explicit
	// set of readiness signals". This way we define an explicit signal rather than rely on the ordering
	// of lines in "runDaemon".
	WaitForSync(context.Context) bool

	ForEachEndpoint(func(*Service, *Endpoints) error) error
}

type ServiceCache interface {
	ServiceLookup

	// TODO kill this weird thing.
	// This is used by redirect policy manager to re-emit events for a cluster IP service after
	// a redirect policy have been removed that shadowed it. Fix this by handling shadowing in
	// service manager.
	EnsureService(svcID k8s.ServiceID) bool

	store.ServiceMerger
	clustermesh.ServiceMerger

	DebugStatus() string
}

var Cell = cell.Module(
	"service-cache",
	"Service Cache stores services and associated endpoints",
	cell.Provide(newServiceCache),

	config.Cell, // FIXME which modules owns this. Sometimes we need just ServiceCache
	// but no ServiceManager.
)

// serviceCacheState captures the internal state. It's a separate struct for DebugStatus().
type serviceCacheState struct {
	services map[ServiceID]*Service

	// endpoints maps a service to a map of EndpointSlices. In case the cluster
	// is still using the v1.Endpoints, the key used in the internal map of
	// EndpointSlices is the v1.Endpoint name.
	endpoints map[ServiceID]*EndpointSlices

	// selfNodeZoneLabel implements the Kubernetes topology aware hints
	// by selecting only the backends in this node's zone.
	selfNodeZoneLabel string

	// externalEndpoints is a list of additional service backends derived from source other than the local cluster
	externalEndpoints map[ServiceID]externalEndpoints
}

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

// DebugStatus implements debug.StatusObject to provide debug status collection
// ability
func (sc *serviceCache) DebugStatus() string {
	sc.mu.RLock()
	str := spew.Sdump(sc.serviceCacheState)
	sc.mu.RUnlock()
	return str
}

func (sc *serviceCache) WaitForSync(ctx context.Context) bool {
	var ctxDone <-chan struct{}
	if ctx != nil {
		ctxDone = ctx.Done()
	}
	select {
	case <-ctxDone:
		return false
	case <-sc.syncChan:
		return true
	}
}

func (sc *serviceCache) Events(ctx context.Context) <-chan *ServiceEvent {
	events := make(chan *ServiceEvent)
	sc.subChan <- &newSub{ctx, events}
	return events
}

func (sc *serviceCache) ForEachEndpoint(apply func(*Service, *Endpoints) error) error {
	sc.mu.RLock()
	defer sc.mu.RUnlock()
	for svcID, epSlice := range sc.endpoints {
		svc := sc.services[svcID]
		for _, ep := range epSlice.EpSlices {
			if err := apply(svc, ep); err != nil {
				return err
			}
		}
	}
	return nil
}

func drain[T any](ch <-chan T) {
	for range ch {
	}
}
