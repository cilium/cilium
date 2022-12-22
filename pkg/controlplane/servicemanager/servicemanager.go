package servicemanager

import (
	"context"

	"github.com/cilium/workerpool"
	"golang.org/x/exp/slices"

	datapathlb "github.com/cilium/cilium/pkg/datapath/lb"
	"github.com/cilium/cilium/pkg/hive"
	lb "github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/lock"
)

func New(p params) ServiceManager {
	sm := &serviceManager{
		wp:         workerpool.New(2),
		datapath:   p.DPLB,
		handlesSWG: lock.NewStoppableWaitGroup(),
		entries:    make(map[lb.ServiceName]serviceEntry),
	}
	return sm
}

// TODO: How does health server hook into this? can either
// embed it here, or provide an event stream to it.

type serviceManager struct {
	mu lock.Mutex

	entries map[lb.ServiceName]serviceEntry

	handlesSWG *lock.StoppableWaitGroup
	wp         *workerpool.WorkerPool

	datapath datapathlb.LoadBalancer
}

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

type serviceHandle struct {
	*serviceManager
	name string
}

func (h *serviceHandle) modifyEntry(name lb.ServiceName, mod func(e *serviceEntry)) {
	h.mu.Lock()
	defer h.mu.Unlock()

	e := h.entries[name]
	mod(&e)

	if e.isZero() {
		delete(h.entries, name)
	} else {
		h.entries[name] = e
	}
}

func (h *serviceHandle) UpsertBackends(name lb.ServiceName, backends ...lb.Backend) {
	h.modifyEntry(name, func(e *serviceEntry) {
		for _, backend := range backends {
			e.backends.upsert(backend)
		}
		e.apply(h.datapath)

		if e.overrideProxyRedirect != nil {
			e.overrideProxyRedirect.backendChanges <- BackendsChanged{
				Name:     name,
				Backends: slices.Clone(e.backends),
			}
		}
	})
}

func (h *serviceHandle) DeleteBackends(name lb.ServiceName, addrs ...lb.L3n4Addr) {
	h.modifyEntry(name, func(e *serviceEntry) {
		for _, addr := range addrs {
			e.backends.delete(&addr)
		}
		e.apply(h.datapath)

		if e.overrideProxyRedirect != nil {
			e.overrideProxyRedirect.backendChanges <- BackendsChanged{
				Name:     name,
				Backends: slices.Clone(e.backends),
			}
		}
	})
}

func (h *serviceHandle) UpsertFrontend(frontend lb.FE) {
	h.modifyEntry(frontend.ServiceName(), func(e *serviceEntry) {
		e.frontends.upsert(frontend)
		e.apply(h.datapath)
	})
}

func (h *serviceHandle) DeleteFrontend(frontend lb.FE) {
	addr := frontend.Address()
	h.modifyEntry(frontend.ServiceName(), func(e *serviceEntry) {
		e.frontends.delete(addr)
		h.datapath.Delete(*addr)
	})
}

func (h *serviceHandle) SetProxyRedirect(name lb.ServiceName, proxyPort uint16, backendChanges chan<- BackendsChanged) {
	h.modifyEntry(name, func(e *serviceEntry) {
		e.overrideProxyRedirect = &overrideProxyRedirect{proxyPort: proxyPort, backendChanges: backendChanges}
		e.apply(h.datapath)
	})
}

func (h *serviceHandle) RemoveProxyRedirect(name lb.ServiceName) {
	h.modifyEntry(name, func(e *serviceEntry) {
		e.overrideProxyRedirect = nil
		e.apply(h.datapath)
	})
}

func (h *serviceHandle) SetLocalRedirect(name lb.ServiceName, localBackends []lb.Backend) {
	h.modifyEntry(name, func(e *serviceEntry) {
		e.overrideLocalRedirect = &overrideLocalRedirect{
			localBackends: localBackends,
		}
		e.apply(h.datapath)
	})
}

func (h *serviceHandle) RemoveLocalRedirect(name lb.ServiceName) {
	h.modifyEntry(name, func(e *serviceEntry) {
		e.overrideLocalRedirect = nil
		e.apply(h.datapath)
	})
}

func (h *serviceHandle) Synchronized() {
	h.handlesSWG.Done()
}

func (h *serviceHandle) Close() {
	panic("TODO fix proxy redirect backend changes sending")
	// on close() need to make all sends to backendChanges channels registered by this handle into no-ops.
}

var _ ServiceHandle = &serviceHandle{}
