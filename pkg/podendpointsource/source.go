// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package podendpointsource

import (
	"context"
	"log/slog"
	"net"
	"net/netip"
	"slices"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/stream"

	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/identity"
	identityCache "github.com/cilium/cilium/pkg/identity/cache"
	"github.com/cilium/cilium/pkg/ipcache"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/time"
)

// Source exposes pod endpoints, aggregated across all IPs of each pod, as a
// stream of [Event]s.
//
// Source subscribes to the IPCache on behalf of its consumers, filters out
// entries that are not pod endpoints (non-local cluster, non-/32 or non-/128
// prefixes, and entries without Kubernetes metadata), resolves identity
// labels via the IdentityAllocator, and emits deduplicated per-pod events
// that match the semantics previously provided by CiliumEndpoint watchers.
//
// Source is safe for concurrent use. Subscribers should consume events via
// [job.Observer] so that event delivery is automatically bounded by the
// job's context. On subscription the current state is replayed as a sequence
// of Upsert events, after which live updates are delivered.
type Source interface {
	stream.Observable[Event]
}

// queueSize bounds the internal channel between the IPCache listener
// callback and the consumer goroutine. The consumer is cheap (one identity
// lookup and a map update per event), so the buffer only needs to absorb
// short bursts during the IPCache dump and transient storms. A larger value
// trades a small amount of memory for resilience against head-of-line
// blocking of the IPCache.
const queueSize = 4096

// blockedWarnInterval throttles the "enqueue is blocking" warning so that a
// sustained overload condition does not flood the logs.
const blockedWarnInterval = 30 * time.Second

// callbackEvent is the internal representation of an IPCache change,
// decoupled from the [ipcache.IPIdentityMappingListener] signature so that
// the callback can return immediately.
//
// For Upsert events, namespace/podName come from the "new" K8sMetadata and
// identify the pod that owns the IP after the change. For Delete events,
// they come from the "old" K8sMetadata (as passed by IPCache) and identify
// the pod that owned the IP before the change. In both cases hasMeta
// discriminates between an event for a pod endpoint and an event for a
// non-pod source (CIDR, world identity, etc.).
type callbackEvent struct {
	modType ipcache.CacheModification
	addr    netip.Addr
	newID   identity.NumericIdentity
	hostIP  string

	namespace string
	podName   string
	hasMeta   bool
}

// source is the default [Source] implementation backed by an IPCache
// listener.
type source struct {
	logger *slog.Logger

	identityAllocator identityCache.IdentityAllocator

	// queue carries pre-filtered IPCache events from the listener
	// callback to the consumer goroutine. A bounded channel bounds
	// memory and provides backpressure; the callback blocks when the
	// queue is full so no events are ever lost.
	queue chan callbackEvent

	// mu protects endpoints and ipToID during Observe replay. All state
	// mutations happen from a single consumer goroutine, so mu is only
	// contended when a new subscriber is attaching.
	mu        lock.RWMutex
	endpoints map[string]*PodEndpoint
	ipToID    map[netip.Addr]string

	// observable is the live event stream. emit and complete are its
	// producer-side handles; see [stream.Multicast].
	observable stream.Observable[Event]
	emit       func(Event)
	complete   func(error)

	// lastBlockedWarn throttles the log line emitted when the callback
	// has to block on a full queue.
	lastBlockedWarn struct {
		lock.Mutex
		t time.Time
	}
}

type params struct {
	cell.In

	Logger            *slog.Logger
	Lifecycle         cell.Lifecycle
	JobGroup          job.Group
	IPCache           *ipcache.IPCache
	IdentityAllocator identityCache.IdentityAllocator
}

func newSource(p params) Source {
	s := &source{
		logger:            p.Logger,
		identityAllocator: p.IdentityAllocator,
		queue:             make(chan callbackEvent, queueSize),
		endpoints:         map[string]*PodEndpoint{},
		ipToID:            map[netip.Addr]string{},
	}
	s.observable, s.emit, s.complete = stream.Multicast[Event]()

	// Run the consumer goroutine for the lifetime of the cell.
	p.JobGroup.Add(job.OneShot("pod-endpoint-source", s.run))

	// Register the IPCache listener after the global identity cache is
	// warmed up, so identity lookups in the consumer goroutine succeed
	// for the IPs delivered by the initial dump. This is done in a job
	// rather than an OnStart hook because WaitForInitialGlobalIdentities
	// depends on work (such as [identity/cache.CachingIdentityAllocator.InitIdentityAllocator])
	// performed by other OnStart hooks — notably the legacy daemon cell —
	// and blocking here would prevent those later hooks from running
	// inside the lifecycle's sequential start pass.
	p.JobGroup.Add(job.OneShot(
		"pod-endpoint-listener-registration",
		func(ctx context.Context, _ cell.Health) error {
			if err := p.IdentityAllocator.WaitForInitialGlobalIdentities(ctx); err != nil {
				return err
			}
			p.IPCache.AddListener(s)
			return nil
		},
	))

	p.Lifecycle.Append(cell.Hook{
		OnStop: func(cell.HookContext) error {
			// The job group's context cancellation will stop the
			// consumer; signal subscribers that the observable is
			// complete so that any pending Observe calls unblock.
			s.complete(nil)
			return nil
		},
	})

	return s
}

// Observe replays the current set of pod endpoints as a sequence of Upsert
// events and then delegates to the live multicast observable. It is safe to
// subscribe at any time after the cell has been constructed.
//
// The replay holds a read lock on the source's state, which is briefly
// contended with the consumer goroutine. This matches the
// "snapshot then subscribe" pattern used by
// pkg/identity/cache/local.localIdentityCache.
func (s *source) Observe(ctx context.Context, next func(Event), complete func(error)) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	for _, ep := range s.endpoints {
		select {
		case <-ctx.Done():
			complete(ctx.Err())
			return
		default:
		}
		next(Event{Kind: EventKindUpsert, Endpoint: cloneEndpoint(ep)})
	}

	s.observable.Observe(ctx, next, complete)
}

// OnIPIdentityCacheChange implements [ipcache.IPIdentityMappingListener].
//
// The listener runs with the IPCache lock held, so this function performs
// only cheap filtering before enqueueing the event to the consumer
// goroutine. All heavier work — identity lookup, endpoint mirror mutation,
// event emission — happens downstream of the queue, outside the IPCache
// lock.
func (s *source) OnIPIdentityCacheChange(
	modType ipcache.CacheModification,
	cidrCluster cmtypes.PrefixCluster,
	_ net.IP, newHostIP net.IP,
	_ *ipcache.Identity, newID ipcache.Identity,
	_ uint8,
	k8sMeta *ipcache.K8sMetadata,
	_ uint8,
) {
	// Only process local cluster entries. Remote clustermesh entries
	// (non-zero ClusterID) previously were not observed by the CiliumEndpoint
	// watcher; mirroring that behaviour prevents namespace/name collisions
	// with local pods and keeps remote traffic out of the local gateway
	// decision path.
	if cidrCluster.ClusterID() != 0 {
		return
	}

	// Only pod endpoints are of interest. A pod IP is represented by a
	// host-length prefix (/32 for IPv4, /128 for IPv6). Reject CIDR
	// entries up-front so that we never enqueue an event for them.
	prefix := cidrCluster.AsPrefix()
	addr := prefix.Addr()
	if !addr.IsValid() {
		return
	}
	switch {
	case addr.Is4() && prefix.Bits() == 32:
	case !addr.Is4() && prefix.Bits() == 128:
	default:
		return
	}

	ev := callbackEvent{
		modType: modType,
		addr:    addr,
		newID:   newID.ID,
	}
	if newHostIP != nil {
		ev.hostIP = newHostIP.String()
	}
	if k8sMeta != nil && k8sMeta.Namespace != "" && k8sMeta.PodName != "" {
		// Copy out the fields we need. K8sMetadata is owned by the
		// IPCache and must not be retained by listeners.
		ev.namespace = k8sMeta.Namespace
		ev.podName = k8sMeta.PodName
		ev.hasMeta = true
	}

	// Fast path: non-blocking send. On overflow fall back to a blocking
	// send with a throttled warning so we never lose events.
	select {
	case s.queue <- ev:
	default:
		s.warnBlocked()
		s.queue <- ev
	}
}

func (s *source) warnBlocked() {
	now := time.Now()
	s.lastBlockedWarn.Lock()
	defer s.lastBlockedWarn.Unlock()
	if now.Sub(s.lastBlockedWarn.t) < blockedWarnInterval {
		return
	}
	s.lastBlockedWarn.t = now
	s.logger.Warn(
		"pod-endpoint-source event queue is full; IPCache listener is blocking. "+
			"This may indicate slow subscribers or a sustained IPCache update storm.",
		logfields.Capacity, cap(s.queue),
	)
}

// run consumes events from the queue until ctx is cancelled.
//
// The health argument is unused: this job does not have a notion of
// "degraded" vs "healthy" — it either runs or it doesn't.
func (s *source) run(ctx context.Context, _ cell.Health) error {
	for {
		select {
		case <-ctx.Done():
			return nil
		case ev := <-s.queue:
			s.handleEvent(ev)
		}
	}
}

func (s *source) handleEvent(ev callbackEvent) {
	switch ev.modType {
	case ipcache.Upsert:
		if ev.hasMeta {
			s.upsertPodIP(ev)
		} else {
			// The same IP is now associated with something other
			// than a pod (e.g. a CIDR identity). Evict any prior
			// pod owner so the mirror doesn't leak.
			s.evictIP(ev.addr)
		}
	case ipcache.Delete:
		if ev.hasMeta {
			// Scope the eviction to the pod that IPCache says
			// owned the IP before this delete. If the IP has
			// since been reassigned to a different pod (e.g. the
			// source has already applied a synthetic eviction in
			// upsertPodIP for a pod-a→pod-b reassignment, and this
			// delete is the stale one for pod-a), this check
			// prevents the stale delete from erasing the new pod.
			s.evictIPForPod(ev.addr, ev.namespace+"/"+ev.podName)
		} else {
			// Delete of a non-pod entry. If a pod currently owns
			// this IP we still want to evict it, for the same
			// leak-prevention reason as the Upsert-without-meta
			// path above.
			s.evictIP(ev.addr)
		}
	}
}

// upsertPodIP applies an Upsert for an IPCache entry that carries pod
// metadata. It handles three cases uniformly:
//   - the pod+IP pair is new
//   - the pod already exists and the IP is added to it
//   - the IP previously belonged to a different pod (reassignment)
func (s *source) upsertPodIP(ev callbackEvent) {
	epID := ev.namespace + "/" + ev.podName

	// Identity lookup may internally go to the kvstore. Do it outside
	// any of our locks so that a slow lookup never blocks a concurrent
	// Observe replay on a new subscriber.
	labels, identityOK := s.lookupIdentityLabels(ev.newID)

	// The state mutation and the corresponding emit are performed under
	// a single critical section so that a new subscriber's
	// snapshot-then-subscribe in [source.Observe] cannot race with a
	// half-applied update and observe the same Upsert twice.
	s.mu.Lock()
	defer s.mu.Unlock()

	// If this IP is currently owned by a different endpoint, remove it
	// from that endpoint first. This covers pod-to-pod IP reassignment
	// without waiting for the stale Delete to arrive.
	if prevID, owned := s.ipToID[ev.addr]; owned && prevID != epID {
		if evicted := s.removeIPLocked(prevID, ev.addr); evicted != nil {
			s.emit(*evicted)
		}
	}

	ep, exists := s.endpoints[epID]
	if !identityOK {
		if !exists {
			// Without labels we cannot match any policy, so
			// creating a new endpoint here would only produce a
			// degenerate entry. Skip it; a subsequent IPCache
			// upsert will redeliver once the identity is
			// resolvable.
			s.logger.Debug(
				"Skipping pod endpoint upsert: identity not resolvable",
				logfields.Identity, ev.newID,
				logfields.K8sNamespace, ev.namespace,
				logfields.K8sPodName, ev.podName,
			)
			return
		}
		// Preserve the previously-known labels rather than wiping
		// them to empty. The endpoint still has its current IPs and
		// node IP updated.
		labels = ep.Labels
		s.logger.Debug(
			"Preserving last-known labels for pod endpoint: identity not resolvable",
			logfields.Identity, ev.newID,
			logfields.K8sNamespace, ev.namespace,
			logfields.K8sPodName, ev.podName,
		)
	}

	if !exists {
		ep = &PodEndpoint{
			ID:     epID,
			IPs:    []netip.Addr{ev.addr},
			Labels: labels,
			NodeIP: ev.hostIP,
		}
		s.endpoints[epID] = ep
	} else {
		ep.Labels = labels
		ep.NodeIP = ev.hostIP
		if !slices.Contains(ep.IPs, ev.addr) {
			ep.IPs = append(ep.IPs, ev.addr)
			sortIPs(ep.IPs)
		}
	}
	s.ipToID[ev.addr] = epID

	s.emit(Event{Kind: EventKindUpsert, Endpoint: cloneEndpoint(ep)})
}

// evictIP drops an IP from whichever endpoint currently owns it, if any,
// and emits the appropriate Upsert or Delete event.
func (s *source) evictIP(addr netip.Addr) {
	s.mu.Lock()
	defer s.mu.Unlock()

	prevID, owned := s.ipToID[addr]
	if !owned {
		return
	}
	if ev := s.removeIPLocked(prevID, addr); ev != nil {
		s.emit(*ev)
	}
}

// evictIPForPod drops an IP, but only if it is currently attributed to the
// given pod. It is the ownership-scoped variant of evictIP used for
// pod-targeted Delete events.
//
// This is the primary defence against stale Delete events clobbering a pod
// that has just taken over the IP. A reassignment pod-a → pod-b is handled
// eagerly in upsertPodIP by removing the IP from pod-a; if a stale delete
// for pod-a then arrives, ipToID[addr] already points at pod-b and this
// function leaves pod-b untouched.
func (s *source) evictIPForPod(addr netip.Addr, epID string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	prevID, owned := s.ipToID[addr]
	if !owned || prevID != epID {
		return
	}
	if ev := s.removeIPLocked(prevID, addr); ev != nil {
		s.emit(*ev)
	}
}

// removeIPLocked removes addr from the endpoint identified by epID. It
// returns the Event that should be emitted to subscribers to describe the
// change, or nil if no change is observable (which can only happen if epID
// or addr cannot be found — a defensive code path).
//
// Must be called with s.mu held.
func (s *source) removeIPLocked(epID string, addr netip.Addr) *Event {
	delete(s.ipToID, addr)

	ep, ok := s.endpoints[epID]
	if !ok {
		return nil
	}
	ep.IPs = slices.DeleteFunc(ep.IPs, func(a netip.Addr) bool { return a == addr })
	if len(ep.IPs) == 0 {
		delete(s.endpoints, epID)
		return &Event{
			Kind:     EventKindDelete,
			Endpoint: PodEndpoint{ID: epID},
		}
	}
	return &Event{Kind: EventKindUpsert, Endpoint: cloneEndpoint(ep)}
}

// lookupIdentityLabels resolves an identity ID to its labels in the
// Kubernetes string-map form. The bool return signals whether the identity
// was resolvable; the caller decides how to treat an unresolved identity.
func (s *source) lookupIdentityLabels(id identity.NumericIdentity) (map[string]string, bool) {
	ident := s.identityAllocator.LookupIdentityByID(context.Background(), id)
	if ident == nil {
		return nil, false
	}
	return ident.Labels.K8sStringMap(), true
}

// cloneEndpoint returns a detached copy of ep that is safe to hand out to
// subscribers without risking mutation of the source's internal state.
func cloneEndpoint(ep *PodEndpoint) PodEndpoint {
	out := PodEndpoint{
		ID:     ep.ID,
		NodeIP: ep.NodeIP,
		IPs:    slices.Clone(ep.IPs),
	}
	if ep.Labels != nil {
		out.Labels = make(map[string]string, len(ep.Labels))
		for k, v := range ep.Labels {
			out.Labels[k] = v
		}
	}
	return out
}

// sortIPs orders IPs so that IPv4 addresses come first, then IPv6, numeric
// within each family. This matches the ordering that the previous
// CiliumEndpoint-based source produced.
func sortIPs(ips []netip.Addr) {
	slices.SortFunc(ips, func(a, b netip.Addr) int {
		switch {
		case a.Is4() && !b.Is4():
			return -1
		case !a.Is4() && b.Is4():
			return 1
		default:
			return a.Compare(b)
		}
	})
}

// Ensure interface satisfaction at compile time.
var (
	_ ipcache.IPIdentityMappingListener = (*source)(nil)
	_ Source                            = (*source)(nil)
)
