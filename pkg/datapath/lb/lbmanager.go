package lb

import (
	"context"
	"fmt"

	"github.com/cilium/cilium/pkg/container"
	"github.com/cilium/cilium/pkg/counter"
	datapathTypes "github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"k8s.io/client-go/util/workqueue"
)

type DatapathLoadBalancing interface { // or "LBMap"?
	Upsert(id loadbalancer.FrontendID, svc *loadbalancer.Frontend, backends []*loadbalancer.Backend)
	Delete(id loadbalancer.FrontendID)

	GarbageCollect()
}

type svcRequest struct {
	hash     frontendHash
	svc      *loadbalancer.Frontend
	backends []*loadbalancer.Backend
}

type backendHash = string // XXX not really a hash. (L3n4Addr.Hash)

// State of a single service. Reflects the current state in BPF maps
// and is used to compute the changes needed when applying a request.
//
// A failed request may succeed partially which is reflected in the
// state and on retry only the remaining changes are processed.
type svcState struct {
	id       uint16 // FIXME overlap with "id" in FrontendID
	fe       *loadbalancer.Frontend
	backends container.Set[backendHash]
	// ... ?
}

// TODO: What to call this thing? lbmapManager? Or just merge into lbmap?
type lbManager struct {
	// state is the actualized state of the service and its backends.
	state map[frontendHash]*svcState

	serviceIDs map[frontendHash]uint16

	backendIDs      map[backendHash]loadbalancer.BackendID
	backendRefCount counter.Counter[backendHash]

	// FIXME: need to use service.IDAllocator to deal with reuse. Move it
	// to pkg/datapath/loadbalancing.
	frontendIDAlloc *IDAllocator
	backendIDAlloc  *IDAllocator

	lbmap datapathTypes.LBMap
}

func (m *lbManager) restoreFromBPF() {
	// TODO: only need to restore frontend and backend id allocation?
}

func (m *lbManager) garbageCollect() {
	// TODO:
	// - remove services from services bpf map that are not in
	//   m.state.
	// - remove backends that are not referenced by any services.
}

func (m *lbManager) delete(hash frontendHash) error {
	state, ok := m.state[hash]
	if !ok {
		panic("TBD not found")
	}

	err := m.lbmap.DeleteService(
		loadbalancer.L3n4AddrID{L3n4Addr: state.fe.Address, ID: loadbalancer.ID(state.id)},
		len(state.backends),
		false, // FIXME useMaglev, from config.
		state.fe.NatPolicy,
	)
	if err != nil {
		return err
	}

	// Clean up backends
	for hash := range state.backends {
		if m.backendRefCount.Delete(hash) {
			panic("TODO delete")
		}
		state.backends.Delete(hash)
	}

	// Now that deletion completed successfully we can forget the
	// frontend.
	delete(m.state, hash)

	return nil
}

func (m *lbManager) upsert(hash frontendHash, frontend *loadbalancer.Frontend, backends []*loadbalancer.Backend) error {
	// This method is written to be retryable. The state of the frontend is updated after each
	// successful step. On early return of an error the upsert request will be retried and this
	// method continues from where it last failed based on the state. The assumption is that
	// errors encountered here are mostly due to either low memory (spurious ENOMEM), or BPF maps being
	// full (ENOSPC) and retrying (with backoff) allows user intervention to make more space and
	// to eventually recover.

	state, ok := m.state[hash]
	if !ok {
		addrId, err := m.frontendIDAlloc.acquireLocalID(frontend.Address, 0)
		if err != nil {
			// FIXME more information to error. We probably want to classify errors
			// into few categories and provide useful hints to the operator on how
			// they can help to recover from this.
			return err
		}
		state.id = uint16(addrId.ID)
	}

	// FIXME: expand the backends in the request into the
	// real set based on device IPs etc.

	// Compute the new set of backends for this service
	// and update ref counts.
	newBackends := map[backendHash]*loadbalancer.Backend{}
	newBackendsSet := container.NewSet[backendHash]()
	for _, backend := range backends {
		hash := backend.Hash()
		if !state.backends.Contains(hash) {
			m.backendRefCount.Add(hash)
			newBackends[hash] = backend
			newBackendsSet.Add(hash)
		}
	}

	// Clean up removed backends.
	prevBackendsCount := len(state.backends)
	for hash := range state.backends {
		if !newBackendsSet.Contains(hash) {
			state.backends.Delete(hash)
			if m.backendRefCount.Delete(hash) {
				panic("TODO actually delete the entry")
			}
		}
	}

	// Create the missing backend entries.
	missingBackends := newBackendsSet.Clone().Sub(state.backends)
	for hash := range missingBackends {
		be := newBackends[hash]
		if _, ok := m.backendIDs[hash]; !ok {
			addrId, err := m.backendIDAlloc.acquireLocalID(frontend.Address, 0)
			if err != nil {
				return err
			}
			id := loadbalancer.BackendID(addrId.ID)

			// FIXME: change the LBMap types
			legacyBE := &loadbalancer.Backend{
				ID:         id,
				FEPortName: be.FEPortName,
				Weight:     be.Weight,
				NodeName:   be.NodeName,
				L3n4Addr:   be.L3n4Addr,
				State:      be.State,
				Preferred:  be.Preferred,
			}
			if err := m.lbmap.AddBackend(legacyBE, be.IsIPv6()); err != nil {
				return fmt.Errorf("failure while adding backend %d (%s): %w", id,
					be.L3n4Addr.String(), err)
			}

			m.backendIDs[hash] = id
			state.backends.Add(hash)
		}
	}

	// FIXME: We really only need the backend id and its weight, not all the data.
	// Perhaps even could update the maglev maps separately.
	legacyBackends := map[string]*loadbalancer.Backend{}
	for hash, be := range newBackends {
		legacyBE := &loadbalancer.Backend{
			ID:         loadbalancer.BackendID(m.backendIDs[hash]),
			FEPortName: be.FEPortName,
			Weight:     be.Weight,
			NodeName:   be.NodeName,
			L3n4Addr:   be.L3n4Addr,
			State:      be.State,
			Preferred:  be.Preferred,
		}
		legacyBackends[hash] = legacyBE
	}

	// Update the service entry
	params := datapathTypes.UpsertServiceParams{
		ID:   state.id,
		IP:   frontend.Address.AddrCluster.AsNetIP(),
		Port: frontend.Address.Port,
		// TODO: We need backend ID and its weight for LBMap.
		PreferredBackends:         map[string]*loadbalancer.Backend{},
		ActiveBackends:            map[string]*loadbalancer.Backend{},
		NonActiveBackends:         []loadbalancer.BackendID{},
		PrevBackendsCount:         prevBackendsCount, // Used to clean up unused slots.
		IPv6:                      frontend.Address.IsIPv6(),
		Type:                      frontend.Type,
		NatPolicy:                 frontend.NatPolicy,
		Local:                     false, // FIXME svcInfo.requireNodeLocalBackends
		Scope:                     frontend.Address.Scope,
		SessionAffinity:           frontend.SessionAffinity,
		SessionAffinityTimeoutSec: frontend.SessionAffinityTimeoutSec,
		CheckSourceRange:          false, // FIXME need to update and stuff, see service.go:1298
		UseMaglev:                 false, // FIXME depends on svc type and node port alg  (who owns this option?)
		L7LBProxyPort:             frontend.L7LBProxyPort,
		Name:                      frontend.Name,
		LoopbackHostport:          frontend.LoopbackHostport,
	}

	if err := m.lbmap.UpsertService(&params); err != nil {
		// FIXME delete the created backends, or leave them around as we keep
		// retrying? Can consider doing a GC based on diff of backendIDs and backendRefCount.
		return err
	}

	// Now that both the frontend and the backends were all successfully created
	// we can update refcounts and persist the state.
	for hash := range state.backends {
		m.backendRefCount.Add(hash)
	}
	m.state[hash] = state
	return nil
}

type frontendHash = string

// lbWorker manages the queueing and retrying of incoming
// control-plane requests
type lbWorker struct {
	m *lbManager

	unrealized map[frontendHash]*svcRequest
	wq         workqueue.RateLimitingInterface

	requests chan *svcRequest
	work     chan frontendHash
	gc       chan struct{}
}

func (m *lbWorker) worker(ctx context.Context) {
	for {
		item, shutdown := m.wq.Get()
		if shutdown {
			return
		}
		m.work <- item.(frontendHash)
	}
}

func (w *lbWorker) processLoop(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return

		case hash := <-w.work:
			req := w.unrealized[hash]
			var err error

			if req.svc == nil {
				err = w.m.upsert(hash, req.svc, req.backends)
			} else {
				err = w.m.delete(hash)
			}
			if err != nil {
				// TODO: Status reports. Would be good to keep track of what things we're retrying and
				// what the last failure was so it can be queried. It'd be nice to have
				// structured data in the error (e.g. stuff the "WithFields" we log (lbmap.go:139)).
				// TODO: Metrics
				// TODO: Would we always want to log the failure (might cause a lot of logging if we
				// end up with full BPF map, or would periodic reporting of "faulty state" make more sense?
				w.wq.AddRateLimited(hash)
			} else {
				w.wq.Forget(hash)
				delete(w.unrealized, hash)
			}
			w.wq.Done(hash)

		case req := <-w.requests:
			w.unrealized[req.hash] = req
			w.wq.Add(req.hash)

		case <-w.gc:
			panic("TBD")
			// We would end up here when the control-plane has finished the initial synchronization
			// with upstream data sources and all relevant upsert/delete's have been processed.
			// TODO: make sure we don't GC if there's failed requests in the queue!
			// We would garbage collect all "unknown" entries from the BPF maps.
			// (need to keep track of what was touched).
		}
	}
}

func (w *lbWorker) Upsert(fe *loadbalancer.Frontend, backends ...*loadbalancer.Backend) {
	w.requests <- &svcRequest{fe.Address.Hash(), fe, backends}
}

func (w *lbWorker) Delete(frontend loadbalancer.L3n4Addr) {
	w.requests <- &svcRequest{frontend.Hash(), nil, nil}
}

func (w *lbWorker) GarbageCollect() {
	w.gc <- struct{}{}
}
