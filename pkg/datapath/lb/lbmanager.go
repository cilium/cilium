package lb

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/cilium/workerpool"
	"k8s.io/client-go/util/workqueue"

	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/container"
	"github.com/cilium/cilium/pkg/counter"
	datapathTypes "github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/status"
	"github.com/cilium/cilium/pkg/testutils/mockmaps"
	"github.com/cilium/cilium/test/controlplane/helpers"
)

type LoadBalancer interface {
	Upsert(svc *loadbalancer.SVC)
	Delete(addr loadbalancer.L3n4Addr)
	GarbageCollect()

	// TODO: some way querying the status if we need to report back up
	// to users via e.g. k8s object's Status. Event channel?
}

var Cell = cell.Module(
	"datapath-loadbalancer",
	"Manages the BPF state for load-balancing",

	cell.Config(DefaultConfig),
	cell.ProvidePrivate(newLBManager),
	cell.Provide(newLBWorker),
)

// newLBWorker creates a new load-balancer worker that implements LoadBalancer API.
// The worker applies requests sequentially and retries failed requests. Requests
// for the same frontend will be coalesced.
func newLBWorker(lc hive.Lifecycle, m *lbManager, r status.Reporter) LoadBalancer {
	return (*lbWorker)(newWorker[frontendKey](lc, m, r))
}

type (
	frontendKey = string
	backendKey  = string
)

// State of a single frontend. Reflects the current state in BPF maps
// and is used to compute the changes needed when applying a request.
//
// A failed request may succeed partially which is reflected in the
// state and on retry only the remaining changes are processed.
type feState struct {
	id       uint16 // FIXME overlap with "id" in FrontendID
	svc      *loadbalancer.SVC
	backends container.Set[backendKey]
	// ... ?
}

// TODO: What to call this thing? lbmapManager? Or just merge into lbmap?
type lbManager struct {
	config Config

	// states contains the actualized states of the frontends.
	states map[frontendKey]*feState

	// TODO: a bit too much going on here. consider separating
	// backend and frontend state and methods into their own things?

	nodePortFrontends map[frontendKey]container.Set[frontendKey]

	frontendIDs map[frontendKey]uint16

	backendIDs      map[backendKey]loadbalancer.BackendID
	backendRefCount counter.Counter[backendKey]

	frontendIDAlloc *IDAllocator
	backendIDAlloc  *IDAllocator

	lbmap datapathTypes.LBMap
}

func newLBManager(config Config, lbmap datapathTypes.LBMap) *lbManager {
	return &lbManager{
		config:            config,
		states:            make(map[frontendKey]*feState),
		frontendIDs:       make(map[frontendKey]uint16),
		backendIDs:        make(map[backendKey]loadbalancer.BackendID),
		nodePortFrontends: make(map[frontendKey]container.Set[frontendKey]),
		backendRefCount:   make(counter.Counter[backendKey]),
		frontendIDAlloc:   NewIDAllocator(0, 100), // FIXME
		backendIDAlloc:    NewIDAllocator(0, 100), // FIXME
		lbmap:             lbmap,
	}
	// TODO: add lifecycle hook which does restoreFromBPF()?
}

func (m *lbManager) restoreFromBPF() {
	backends, err := m.lbmap.DumpBackendMaps()
	if err != nil {
		// TODO how would we handle this error? If we retry, we should not allow other
		// requests through yet.
		panic("TODO DumpBackendMaps")
	}

	for _, be := range backends {
		_, err := m.backendIDAlloc.acquireLocalID(be.L3n4Addr, uint32(be.ID))
		if err != nil {
			panic("TODO acquireLocalID")
		}
		m.backendIDs[be.L3n4Addr.Hash()] = be.ID
	}

	frontends, errs := m.lbmap.DumpServiceMaps()
	if len(errs) != 0 {
		// TODO how would we handle this error? If we retry, we should not allow other
		// requests through yet.
		panic("TODO DumpServiceMaps")
	}

	for _, fe := range frontends {
		_, err := m.frontendIDAlloc.acquireLocalID(fe.Frontend.L3n4Addr, uint32(fe.Frontend.ID))
		if err != nil {
			panic("TODO acquireLocalID")
		}
		m.frontendIDs[fe.Frontend.L3n4Addr.Hash()] = uint16(fe.Frontend.ID)
	}
}

func (m *lbManager) garbageCollect() error {
	// TODO:
	// - assume restoreFromBPF has added to backendIDs and frontendIDs
	// - remove frontends referred to by frontendIDs that are not in m.states.
	// - remove backends that have zero refcount.
	return nil
}

func (m *lbManager) periodicStateCheck() error {
	// TODO: should we do a periodic check to make sure BPF state
	// matches with what we'd expect? We'll need to then hold onto
	// all the data (e.g. currently missing backend data).
	return nil
}

func (m *lbManager) deleteFrontend(key frontendKey) error {
	state, ok := m.states[key]
	if !ok {
		// TODO can we end up here? log warning?
		return nil
	}

	err := m.lbmap.DeleteService(
		loadbalancer.L3n4AddrID{L3n4Addr: state.svc.Frontend.L3n4Addr, ID: loadbalancer.ID(state.id)},
		len(state.backends),
		useMaglev(m.config, state.svc),
		state.svc.NatPolicy,
	)
	if err != nil {
		return err
	}

	// Clean up backends
	for beKey := range state.backends {
		if m.backendRefCount.Delete(beKey) {
			if err := m.deleteBackend(beKey); err != nil {
				return err
			}
		}
	}

	// Now that deletion completed successfully we can forget the
	// frontend state.
	delete(m.states, key)

	return nil
}

// TODO replace by subscribing to device manager. we'd maintain a current set
// of frontend IPs and use those when frontend is upserted. When they change
// all node port frontends would be recomputed and datapath updated
// (e.g. we'd queue request to lbWorker to recompute... from somewhere).
var dummyNodePortFrontendIPs = []string{
	"0.0.0.0", // surrogate
	"1.2.3.4",
	"2.3.4.5",
}

func (m *lbManager) expandNodePortFrontends(frontend *loadbalancer.SVC) []*loadbalancer.SVC {
	// TODO implement the real thing.
	fes := make([]*loadbalancer.SVC, len(dummyNodePortFrontendIPs))
	for i, ip := range dummyNodePortFrontendIPs {
		fe := *frontend
		fe.Frontend.AddrCluster = cmtypes.MustParseAddrCluster(ip)
		fes[i] = &fe
	}

	return fes
}

func (m *lbManager) upsertFrontend(frontend *loadbalancer.SVC) error {
	if frontend.Type == loadbalancer.SVCTypeNodePort {
		hash := frontend.Frontend.Hash()

		// FIXME: expand to real frontends based on device IPs and call upsert() on each.
		// Need to maintain a mapping from "frontend" to the expanded ones.
		keys := container.NewSet[frontendKey]()
		for _, fe := range m.expandNodePortFrontends(frontend) {
			keys.Add(fe.Frontend.Hash())
			if err := m.upsertSingle(fe); err != nil {
				// TODO: rewind? we might be leaving orphan frontends.
				return err
			}
		}

		/* TODO
		oldKeys := m.nodePortFrontends[hash]
		... delete frontends that no longer should exist.
		... OR can this be fully managed when handling device changes?
		*/

		m.nodePortFrontends[hash] = keys

		return nil
	} else {
		return m.upsertSingle(frontend)
	}

}

func (m *lbManager) addBackend(key backendKey, be *loadbalancer.Backend) error {
	if _, ok := m.backendIDs[key]; ok {
		// Existing backend, nothing to do.
		return nil
	}
	addrId, err := m.backendIDAlloc.acquireLocalID(be.L3n4Addr, 0)
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
		return fmt.Errorf("adding backend %d (%s) failed: %w", id,
			be.L3n4Addr.String(), err)
	}

	fmt.Printf("LBMANAGER: Created backend %s with id %d\n", be.L3n4Addr.String(), id)
	m.backendIDs[key] = id
	return nil
}

func (m *lbManager) deleteBackend(key backendKey) error {
	id, ok := m.backendIDs[key]
	if !ok {
		return nil
	}

	if err := m.lbmap.DeleteBackendByID(id); err != nil {
		return fmt.Errorf("deleting backend %d failed: %w", id, err)
	}

	delete(m.backendIDs, key)
	return nil
}

func (m *lbManager) upsertSingle(frontend *loadbalancer.SVC) error {
	backends := frontend.Backends
	// This method is written to be idempotent and thus retryable. The state of the frontend is updated after each
	// successful step. On early return of an error the upsert request will be retried and this
	// method continues from where it last failed based on the state. The assumption is that
	// errors encountered here are mostly due to either low memory (spurious ENOMEM), or BPF maps being
	// full (ENOSPC) and retrying (with backoff) allows user intervention to make more space and
	// to eventually recover.

	fmt.Printf("LBMANAGER: upsert: fe[%s]=%s, nbackends=%d\n", frontend.Type, frontend.Frontend.String(), len(backends))

	frontendKey := frontend.Frontend.Hash()
	state, ok := m.states[frontendKey]
	if !ok {
		addrId, err := m.frontendIDAlloc.acquireLocalID(frontend.Frontend.L3n4Addr, 0)
		if err != nil {
			// FIXME more information to error. We probably want to classify errors
			// into few categories and provide useful hints to the operator on how
			// they can help to recover from this.
			return err
		}
		state = &feState{
			id:       uint16(addrId.ID),
			svc:      frontend,
			backends: container.NewSet[backendKey](),
		}
		m.states[frontendKey] = state
	}

	oldBackends := state.backends

	// Add the new backends.
	state.backends = container.NewSet[backendKey]()
	for _, backend := range backends {
		key := backend.Hash()
		state.backends.Add(key)

		if !oldBackends.Contains(key) {
			if err := m.addBackend(key, &backend); err != nil {
				return err
			}
			m.backendRefCount.Add(frontendKey)
		}
		// TODO: Need to update the backend if state has changed!
	}

	// Clean up orphan backends.
	for key := range oldBackends {
		if !state.backends.Contains(key) {
			if m.backendRefCount.Delete(key) {
				m.deleteBackend(key)
			}
		}
	}

	prevBackendsCount := oldBackends.Len()

	// FIXME: We really only need the backend id and its weight, not all the data.
	// Perhaps even could update the maglev maps separately.
	legacyBackends := map[string]*loadbalancer.Backend{}
	for _, be := range backends {
		key := be.Hash()
		legacyBE := &loadbalancer.Backend{
			ID:         loadbalancer.BackendID(m.backendIDs[key]),
			FEPortName: be.FEPortName,
			Weight:     be.Weight,
			NodeName:   be.NodeName,
			L3n4Addr:   be.L3n4Addr,
			State:      be.State,
			Preferred:  be.Preferred,
		}
		legacyBackends[key] = legacyBE
	}

	// FIXME "requireNodeLocalBackends()"

	// Update the service entry
	params := datapathTypes.UpsertServiceParams{
		ID:                        state.id,
		IP:                        frontend.Frontend.AddrCluster.AsNetIP(),
		Port:                      frontend.Frontend.Port,
		ActiveBackends:            legacyBackends,
		NonActiveBackends:         nil,               // FIXME
		PreferredBackends:         nil,               // FIXME
		PrevBackendsCount:         prevBackendsCount, // Used to clean up unused slots.
		IPv6:                      frontend.Frontend.IsIPv6(),
		Type:                      frontend.Type,
		NatPolicy:                 frontend.NatPolicy,
		Local:                     false, // FIXME svcInfo.requireNodeLocalBackends
		Scope:                     frontend.Frontend.Scope,
		SessionAffinity:           frontend.SessionAffinity,
		SessionAffinityTimeoutSec: frontend.SessionAffinityTimeoutSec,
		CheckSourceRange:          false, // FIXME need to update and stuff, see service.go:1298
		UseMaglev:                 useMaglev(m.config, frontend),
		L7LBProxyPort:             frontend.L7LBProxyPort,
		Name:                      frontend.Name,
		LoopbackHostport:          frontend.LoopbackHostport,
	}
	fmt.Printf("LBMANAGER: Upserting frontend %s (%s:%d) (id %d) with %d backends\n",
		params.Name, params.IP.String(), params.Port, params.ID, len(params.ActiveBackends))

	if err := m.lbmap.UpsertService(&params); err != nil {
		// FIXME delete the created backends, or leave them around as we keep
		// retrying? Can consider doing a GC based on diff of backendIDs and backendRefCount.
		return err
	}

	backendAddrs := []string{}
	for _, be := range backends {
		backendAddrs = append(backendAddrs, be.L3n4Addr.String())
	}

	//fmt.Println("\033[2J\033[H")

	fmt.Printf("LBMANAGER: upsert OK: type=%s, name=%s, frontend=%s, backends=%s\n",
		frontend.Type,
		frontend.Name, frontend.Frontend.String(), strings.Join(backendAddrs, ", "))

	helpers.WriteLBMapAsTable(os.Stdout, m.lbmap.(*mockmaps.LBMockMap))

	return nil
}

func useMaglev(config Config, fe *loadbalancer.SVC) bool {
	if config.NodePortAlg != NodePortAlgMaglev {
		return false
	}
	// Provision the Maglev LUT for ClusterIP only if ExternalClusterIP is
	// enabled because ClusterIP can also be accessed from outside with this
	// setting. We don't do it unconditionally to avoid increasing memory
	// footprint.
	if fe.Type == loadbalancer.SVCTypeClusterIP && !config.ExternalClusterIP {
		return false
	}
	// Wildcarded frontend is not exposed for external traffic.
	if fe.Type == loadbalancer.SVCTypeNodePort && isWildcardAddr(fe.Frontend.L3n4Addr) {
		return false
	}
	// Only provision the Maglev LUT for service types which are reachable
	// from outside the node.
	switch fe.Type {
	case loadbalancer.SVCTypeClusterIP,
		loadbalancer.SVCTypeNodePort,
		loadbalancer.SVCTypeLoadBalancer,
		loadbalancer.SVCTypeHostPort,
		loadbalancer.SVCTypeExternalIPs:
		return true
	}
	return false
}

var (
	wildcardIPv6 = cmtypes.MustParseAddrCluster("::")
	wildcardIPv4 = cmtypes.MustParseAddrCluster("0.0.0.0")
)

// isWildcardAddr returns true if given frontend is used for wildcard svc lookups
// (by bpf_sock).
func isWildcardAddr(frontend loadbalancer.L3n4Addr) bool {
	if frontend.IsIPv6() {
		return wildcardIPv6.Equal(frontend.AddrCluster)
	}
	return wildcardIPv4.Equal(frontend.AddrCluster)
}

type lbWorker worker[frontendKey, *lbManager]

// lbWorker implements the LoadBalancer API.
var _ LoadBalancer = &lbWorker{}

type lbRequest = request[frontendKey, *lbManager]

type upsertRequest struct {
	*loadbalancer.SVC
}

func (r *upsertRequest) key() string { return r.Frontend.Hash() }

func (r *upsertRequest) apply(m *lbManager) error {
	return m.upsertFrontend(r.SVC)
}

func (w *lbWorker) Upsert(fe *loadbalancer.SVC) {
	w.requests <- &upsertRequest{fe}
}

type deleteRequest struct {
	hash string
}

func (r *deleteRequest) key() string { return r.hash }

func (r *deleteRequest) apply(m *lbManager) error {
	return m.deleteFrontend(r.hash)
}

func (w *lbWorker) Delete(frontend loadbalancer.L3n4Addr) {
	w.requests <- &deleteRequest{frontend.Hash()}
}

type gcRequest struct{}

func (r gcRequest) key() string {
	return "__gc__"
}

func (r gcRequest) apply(m *lbManager) error {
	return m.garbageCollect()
}

func (w *lbWorker) GarbageCollect() {
	w.requests <- gcRequest{}
}

//
// Generic workqueue driven worker that processes requests sequentially.
//
// Implemented this as a generic version as this is a pattern we might want to
// potentially reuse.
//
// TODO:
// - What to name this?
// - Should be able to configure error handling behavior and rate limiting
// - Metrics and status? Or an event channel for success and retries? Or both?
// - Move to its own package somewhere

type request[Key comparable, Manager any] interface {
	apply(Manager) error
	key() Key
}

type worker[Key comparable, Manager any] struct {
	mgr      Manager
	wq       workqueue.RateLimitingInterface
	requests chan request[Key, Manager]
	work     chan Key
	reporter status.Reporter
}

func newWorker[Key comparable, Manager any](lc hive.Lifecycle, m Manager, r status.Reporter) *worker[Key, Manager] {
	w := &worker[Key, Manager]{
		mgr:      m,
		wq:       workqueue.NewRateLimitingQueue(workqueue.DefaultControllerRateLimiter()),
		requests: make(chan request[Key, Manager]),
		work:     make(chan Key),
		reporter: r,
	}

	wp := workerpool.New(2)

	lc.Append(hive.Hook{
		OnStart: func(hive.HookContext) error {
			if err := wp.Submit("queueGetter", w.queueGetter); err != nil {
				wp.Close()
				return err
			}
			if err := wp.Submit("processLoop", w.processLoop); err != nil {
				wp.Close()
				return err
			}
			return nil
		},
		OnStop: func(hive.HookContext) error {
			return wp.Close()
		},
	})

	return w
}

func (w *worker[Key, Manager]) queueGetter(context.Context) error {
	defer close(w.work)
	for {
		item, shutdown := w.wq.Get()
		if shutdown {
			return nil
		}
		w.work <- item.(Key)
	}
}

func (w *worker[Key, Manager]) processLoop(ctx context.Context) error {
	retries := container.NewSet[Key]()
	unrealized := make(map[Key]request[Key, Manager])

	w.reporter.OK()
	defer w.reporter.Down("Stopped")

	statusUpdate := func() {
		if len(retries) > 0 {
			w.reporter.Degraded(
				fmt.Sprintf("%d unrealized, %d queued, %d being retried",
					len(unrealized), w.wq.Len(), len(retries)))
		} else {
			w.reporter.OK()
		}
	}

	for {
		select {
		case <-ctx.Done():
			// Shut down the queue and drain the work channel.
			w.wq.ShutDown()
			for range w.work {
			}
			close(w.requests)
			return nil

		case hash := <-w.work:
			req, ok := unrealized[hash]
			if !ok {
				// Since the entry is gone we've already processed it.
				continue
			}

			err := req.apply(w.mgr)
			if err != nil {
				// TODO log/incr metrics/update status/emit event etc.
				// onError callback?
				fmt.Printf("WORKER: req.apply err: %s\n", err)
				w.wq.AddRateLimited(hash)
				retries.Add(hash)
				statusUpdate()
			} else {
				w.wq.Forget(hash)
				delete(unrealized, hash)
				if len(retries) > 0 {
					retries.Delete(hash)
					statusUpdate()
				}
			}
			w.wq.Done(hash)

		case req := <-w.requests:
			unrealized[req.key()] = req
			w.wq.Add(req.key())
		}
	}
}
