package servicemanager

import (
	"context"

	datapathlb "github.com/cilium/cilium/pkg/datapath/lb"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/workerpool"
)

type (
	FrontendID = loadbalancer.FrontendID
	Frontend   = loadbalancer.Frontend
	Backend    = loadbalancer.Backend
)

func New(p params) ServiceManager {
	return &serviceManager{
		wp:         workerpool.New(2),
		dplb:       p.DPLB,
		handlesSWG: lock.NewStoppableWaitGroup(),
		store:      make(serviceStore),
	}
}

// TODO: How does health server hook into this? can either
// embed it here, or provide an event stream to it.

type serviceManager struct {
	mu lock.Mutex

	store      serviceStore
	handlesSWG *lock.StoppableWaitGroup
	wp         *workerpool.WorkerPool

	dplb datapathlb.LoadBalancer
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
		sm.dplb.GarbageCollect()
	}
	return nil
}

func (sm *serviceManager) NewHandle(name string) ServiceHandle {
	sm.handlesSWG.Add()
	return &serviceHandle{sm, name}
}

func (sm *serviceManager) upsert(frontend *Frontend, backends []*Backend) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	id := FrontendID{Address: frontend.Address, Type: frontend.Type}
	if sm.store.upsert(id, frontend, backends) {
		// The upserted frontend is the primary, update datapath.
		sm.dplb.Upsert(frontend, backends)
	}
}

func (sm *serviceManager) delete(id FrontendID) {
	sm.store.delete(id)

	// Look up if there's a lower priority frontend that now
	// become the primary.
	frontend, backends := sm.store.lookupByAddr(id.Address)
	if frontend != nil {
		sm.dplb.Upsert(frontend, backends)
	} else {
		sm.dplb.Delete(id.Address)
	}
}

type serviceHandle struct {
	sm   *serviceManager
	name string
}

var _ ServiceHandle = &serviceHandle{}

func (h *serviceHandle) Synchronized() {
	h.sm.handlesSWG.Done()
}

type iter struct {
	pos   int
	items []frontAndBack
}

func (it *iter) Next() (*Frontend, []*Backend, bool) {
	if it.pos >= len(it.items) {
		return nil, nil, false
	}
	item := it.items[it.pos]
	it.pos++
	return item.Frontend, item.backends, true
}

func (h *serviceHandle) Iter() Iter2[*Frontend, []*Backend] {
	// XXX concurrency blahblah
	it := &iter{}
	for _, fronts := range h.sm.store {
		it.items = append(it.items,
			frontAndBack{
				fronts.services[0].Frontend,
				fronts.services[0].backends,
			})
	}
	return it
}

func (h *serviceHandle) Upsert(frontend *Frontend, backends []*Backend) {
	h.sm.upsert(frontend, backends)
}

func (h *serviceHandle) Delete(id FrontendID) {
	h.sm.delete(id)
}
