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
		wp:   workerpool.New(4),
		dplb: p.DPLB,
	}
}

type serviceManager struct {
	mu lock.Mutex

	store      serviceStore
	handlesSWG lock.StoppableWaitGroup
	wp         *workerpool.WorkerPool

	dplb datapathlb.DatapathLoadBalancing
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

func (sm *serviceManager) upsert(id FrontendID, frontend *Frontend, backends []*Backend) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	if sm.store.upsert(id, frontend, backends) {
		// TODO the boolean return is confusing. Make this more explicit.
		sm.dplb.Upsert(id, frontend, backends)
	}
}

func (sm *serviceManager) delete(id FrontendID) {
	sm.store.delete(id)

	// Look up if there's a lower priority frontend that was
	// now activated.
	frontend, backends := sm.store.lookupByAddr(id.Address)
	if frontend == nil {
		sm.dplb.Delete(id)
	} else {
		sm.dplb.Upsert(id, frontend, backends)
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

// TODO: Or return a pointer? These aren't that big though.
func (*serviceHandle) Iter() Iter2[Frontend, []Backend] {
	panic("unimplemented")
}

func (h *serviceHandle) Upsert(id FrontendID, frontend *Frontend, backends []*Backend) {
	h.sm.upsert(id, frontend, backends)
}

func (h *serviceHandle) Delete(id FrontendID) {
	h.sm.delete(id)
}
