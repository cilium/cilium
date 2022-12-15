package servicemanager

import (
	"context"

	datapathlb "github.com/cilium/cilium/pkg/datapath/lb"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/stream"
	"github.com/cilium/workerpool"
)

type (
	Frontend    = loadbalancer.Frontend
	Backend     = loadbalancer.Backend
	ServiceName = loadbalancer.ServiceName
)

func New(p params) ServiceManager {
	sm := &serviceManager{
		wp:         workerpool.New(2),
		datapath:   p.DPLB,
		handlesSWG: lock.NewStoppableWaitGroup(),
		store:      serviceStore{},
	}
	sm.src, sm.emit, sm.complete = stream.Multicast[Event]()
	return sm
}

// TODO: How does health server hook into this? can either
// embed it here, or provide an event stream to it.

type serviceManager struct {
	mu lock.Mutex

	store      serviceStore
	handlesSWG *lock.StoppableWaitGroup
	wp         *workerpool.WorkerPool

	datapath datapathlb.LoadBalancer

	src      stream.Observable[Event]
	emit     func(Event)
	complete func(error)
}

// TODO: rename to LBManager, LBController or something?
// Not sure what to name its datapath counter-part...
var _ ServiceManager = &serviceManager{}

func (sm *serviceManager) Start(hive.HookContext) error {
	return sm.wp.Submit("synchronize", sm.synchronize)
}

func (sm *serviceManager) Stop(hive.HookContext) error {
	return sm.wp.Close()
}

func (sm *serviceManager) synchronize(ctx context.Context) error {
	sm.handlesSWG.Stop()

	// Wait for all handles that were created prior to starting to
	// synchronize. Yes, this means a handler must take a handle
	// in its constructor.
	select {
	case <-ctx.Done():
	case <-sm.handlesSWG.WaitChannel():
		sm.datapath.GarbageCollect()
	}
	return nil
}

func (sm *serviceManager) NewHandle(name string) ServiceHandle {
	sm.handlesSWG.Add()
	return &serviceHandle{sm, name}
}

type deletedEvent struct {
	name ServiceName
}

func (d deletedEvent) Name() ServiceName                    { return d.name }
func (d deletedEvent) ForEachActiveFrontend(func(Frontend)) {}
func (d deletedEvent) ForEachBackend(func(Backend))         {}

type serviceHandle struct {
	*serviceManager
	name string
}

func (h *serviceHandle) emitEvent(name ServiceName) {
	if entry := h.store[name]; entry != nil {
		h.emit(*entry)
	} else {
		h.emit(deletedEvent{name})
	}
}

func (h *serviceHandle) Events(subCtx context.Context, emitCurrentState bool, name *ServiceName) <-chan Event {
	events := make(chan Event, 128) // TODO buffer size?

	emitEvents := func(mgrCtx context.Context) error {
		h.mu.Lock()
		defer h.mu.Unlock()

		// comboCtx is cancelled if either subscriber cancels or manager is stopped.
		var comboCtx context.Context

		if subCtx != nil {
			var cancel context.CancelFunc
			comboCtx, cancel = context.WithCancel(context.Background())
			go func() {
				select {
				case <-mgrCtx.Done():
				case <-subCtx.Done():
				}
				cancel()
			}()

			// Subscribe to future events. Since we're holding the lock, we won't receive
			// any yet.
			h.src.Observe(
				comboCtx,
				func(event Event) {
					if name != nil && event.Name() != *name {
						return
					}
					events <- event
				},
				func(error) { close(events) },
			)
		} else {
			// No context provided, so skip subscribing to future events.
			comboCtx = mgrCtx
			defer close(events)
		}

		if emitCurrentState {
			for entryName, entry := range h.store {
				if comboCtx.Err() != nil {
					break
				}
				if name != nil && entryName != *name {
					continue
				}
				events <- *entry
			}
		}
		return nil
	}

	h.wp.Submit("events", emitEvents)

	return events
}

func (h *serviceHandle) Iter() <-chan Event {
	return h.Events(nil, true, nil)
}

func (h *serviceHandle) UpsertBackends(name ServiceName, backends ...*loadbalancer.Backend) {
	h.mu.Lock()
	defer h.mu.Unlock()

	h.store.upsertBackends(name, backends)
	h.store.forEachActiveFrontend(name, h.datapath.Upsert)
	h.emitEvent(name)
}

func (h *serviceHandle) DeleteBackends(name ServiceName, addrs ...loadbalancer.L3n4Addr) {
	h.mu.Lock()
	defer h.mu.Unlock()

	h.store.deleteBackends(name, addrs)
	h.store.forEachActiveFrontend(name, h.datapath.Upsert)
	h.emitEvent(name)
}

func (h *serviceHandle) UpsertFrontend(name ServiceName, frontend *loadbalancer.Frontend) {
	h.mu.Lock()
	defer h.mu.Unlock()

	if isPrimary, backends := h.store.upsertFrontend(name, frontend); isPrimary {
		h.datapath.Upsert(frontend, backends)
		h.emitEvent(name)
	}
}

func (h *serviceHandle) DeleteFrontend(name ServiceName, addr loadbalancer.L3n4Addr, svcType loadbalancer.SVCType) {
	h.mu.Lock()
	defer h.mu.Unlock()

	newPrimary, backends := h.store.deleteFrontend(name, addr, svcType)
	if newPrimary != nil {
		// A new frontend took its place
		h.datapath.Upsert(newPrimary, backends)
	} else {
		// All frontends are gone
		h.datapath.Delete(addr)
	}
	h.emitEvent(name)
}

func (h *serviceHandle) Synchronized() {
	h.handlesSWG.Done()
}

var _ ServiceHandle = &serviceHandle{}
