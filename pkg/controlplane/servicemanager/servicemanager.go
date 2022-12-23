package servicemanager

import (
	"context"
	"fmt"

	"github.com/cilium/workerpool"
	"golang.org/x/exp/maps"
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
		handles:    make(map[string]*serviceHandle),
	}
	return sm
}

// TODO: How does health server hook into this? can either
// embed it here, or provide an event stream to it.

type serviceManager struct {
	mu lock.Mutex

	entries map[lb.ServiceName]serviceEntry

	wp *workerpool.WorkerPool

	datapath   datapathlb.LoadBalancer
	handles    map[string]*serviceHandle
	handlesSWG *lock.StoppableWaitGroup
}

var _ ServiceManager = &serviceManager{}

func (sm *serviceManager) Start(hive.HookContext) error {
	return sm.wp.Submit("synchronize", sm.synchronize)
}

func (sm *serviceManager) Stop(hive.HookContext) error {
	if len(sm.handles) != 0 {
		return fmt.Errorf("unclosed handles remain: %v", maps.Keys(sm.handles))
	}
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

	h := &serviceHandle{serviceManager: sm, name: name, events: make(chan Event)}
	sm.handles[name] = h
	return h
}

type serviceHandle struct {
	*serviceManager
	synchronized bool
	name         string
	events       chan Event
}

func (h *serviceHandle) Observe(name lb.ServiceName) {
	h.modifyEntry(name, func(e *serviceEntry) {
		e.observers.Add(h)
	})
}

func (h *serviceHandle) Unobserve(name lb.ServiceName) {
	h.modifyEntry(name, func(e *serviceEntry) {
		e.observers.Delete(h)
	})
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
		for o := range e.observers {
			o.events <- Event{
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
		for o := range e.observers {
			o.events <- Event{
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

func (h *serviceHandle) SetProxyRedirect(name lb.ServiceName, proxyPort uint16) {
	h.modifyEntry(name, func(e *serviceEntry) {
		e.overrideProxyRedirect = &overrideProxyRedirect{owner: h, proxyPort: proxyPort}
		e.apply(h.datapath)
	})
}

func (h *serviceHandle) RemoveProxyRedirect(name lb.ServiceName) {
	h.modifyEntry(name, func(e *serviceEntry) {
		e.overrideProxyRedirect = nil
		e.apply(h.datapath)
	})
}

func (h *serviceHandle) SetLocalRedirects(name lb.ServiceName, config LocalRedirectConfig) {
	h.modifyEntry(name, func(e *serviceEntry) {
		e.overrideLocalRedirect = &overrideLocalRedirect{
			localBackends: config.LocalBackends,
		}
		e.apply(h.datapath)
	})
}

func (h *serviceHandle) RemoveLocalRedirects(name lb.ServiceName) {
	h.modifyEntry(name, func(e *serviceEntry) {
		e.overrideLocalRedirect = nil
		e.apply(h.datapath)
	})
}

func (h *serviceHandle) Events() <-chan Event {
	return h.events
}

func (h *serviceHandle) Synchronized() {
	h.mu.Lock()
	defer h.mu.Unlock()

	if !h.synchronized {
		h.synchronized = true
		h.handlesSWG.Done()
	}
}

func (h *serviceHandle) Close() {
	h.mu.Lock()
	defer h.mu.Unlock()

	delete(h.handles, h.name)

	if !h.synchronized {
		h.handlesSWG.Done()
		h.synchronized = true
	}
	close(h.events)
}

var _ ServiceHandle = &serviceHandle{}
