package servicemanager

import (
	"context"
	"sync"

	"github.com/cilium/cilium/pkg/loadbalancer"
)

func New(p serviceManagerParams) ServiceManager {
	return &serviceManager{}
}

type serviceManager struct {
	store serviceStore
	handlesWG sync.WaitGroup
	requests chan request


	dp DatapathLoadBalancing
}

var _ ServiceManager = &serviceManager{}

func (sm *serviceManager) NewHandle(name string) ServiceHandle {
	return &serviceHandle{sm, name}
}

type request interface {
	serviceID() ServiceID
}

type baseRequest struct {
	id ServiceID
}
func (r baseRequest) serviceID() ServiceID { return r.id }

type upsertRequest struct {
	baseRequest
	svc *Service // optional if only backends are updated
	backends []*Backend
}

type deleteRequest struct {
	baseRequest
}

func (sm *serviceManager) processLoop(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return

		case req := <-sm.requests:
			sm.processRequest(req)
		}
	}
}

func (sm *serviceManager) processRequest(req request) {
	switch req := req.(type) {
	case upsertRequest:
		sm.store.upsert(req.id, req.svc, req.backends)
	case deleteRequest:
		sm.store.delete(req.id)
	}

	id := req.serviceID()
	svc, backends := sm.store.lookup(req.serviceID())
	sm.apply(id, svc, backends)
}

func (sm *serviceManager) apply(id ServiceID, svc *Service, backends []*Backend) {
	if svc == nil {
		sm.dp.Delete(id)
	} else {
		sm.dp.Upsert(id, svc, backends)
	}
}

type serviceHandle struct {
	sm   *serviceManager
	name string
}

var _ ServiceHandle = &serviceHandle{}

// Close implements ServiceHandle
func (*serviceHandle) Close() {
	panic("unimplemented")
}

// DeleteService implements ServiceHandle
func (h *serviceHandle) DeleteService(id ServiceID) {
	h.sm.requests <- deleteRequest{baseRequest{id}}
}

// GetServiceAndBackends implements ServiceHandle
func (*serviceHandle) GetServiceAndBackends(fe loadbalancer.L3n4Addr) (*Service, []*Backend, bool) {
	panic("unimplemented")
}

// Iter implements ServiceHandle
func (*serviceHandle) Iter() Iter2[Service, []Backend] {
	panic("unimplemented")
}

// Synchronized implements ServiceHandle
func (*serviceHandle) Synchronized() {
	panic("unimplemented")
}

func (h *serviceHandle) UpsertService(id ServiceID, svc *Service, backends ...*Backend) {
	h.sm.requests <- upsertRequest{baseRequest{id}, svc, backends}
}

