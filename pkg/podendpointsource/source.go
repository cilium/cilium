// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package podendpointsource

import (
	"context"
	"log/slog"
	"net"
	"net/netip"
	"slices"
	"sync/atomic"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/stream"

	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/identity"
	identityCache "github.com/cilium/cilium/pkg/identity/cache"
	"github.com/cilium/cilium/pkg/ipcache"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

// Source exposes local-cluster pod endpoints as per-pod [Event]s.
//
// It filters IPCache updates down to local-cluster single-IP entries with pod
// metadata, resolves identity labels, and replays current state to new
// subscribers before live updates.
type Source interface {
	stream.Observable[Event]
}

// queueSize absorbs short IPCache update bursts without dropping events.
const queueSize = 4096

// callbackEvent contains only the IPCache fields needed after the callback
// returns. For deletes, metadata identifies the previous owner.
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

	// queue is bounded; the IPCache callback blocks when it is full.
	queue chan callbackEvent

	// mu protects Observe replay against the single writer goroutine.
	mu        lock.RWMutex
	endpoints map[string]*PodEndpoint
	ipToKey   map[netip.Addr]string

	observable stream.Observable[Event]
	emit       func(Event)
	complete   func(error)

	queueWasFull atomic.Bool
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
		ipToKey:           map[netip.Addr]string{},
	}
	s.observable, s.emit, s.complete = stream.Multicast[Event]()

	// Run the consumer goroutine for the lifetime of the cell.
	p.JobGroup.Add(job.OneShot("pod-endpoint-source", s.run))

	// Wait here rather than in OnStart; the identity allocator warms up
	// from other lifecycle hooks.
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
			s.complete(nil)
			return nil
		},
	})

	return s
}

// Observe replays current endpoints as Upsert events, then streams live
// updates.
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
// The listener runs with the IPCache lock held; keep it to cheap filtering
// and enqueueing.
func (s *source) OnIPIdentityCacheChange(
	modType ipcache.CacheModification,
	cidrCluster cmtypes.PrefixCluster,
	_ net.IP, newHostIP net.IP,
	_ *ipcache.Identity, newID ipcache.Identity,
	_ uint8,
	k8sMeta *ipcache.K8sMetadata,
	_ uint8,
) {
	// namespace/podName is only unique within the local cluster.
	if cidrCluster.ClusterID() != 0 {
		return
	}

	prefix := cidrCluster.AsPrefix()
	addr := prefix.Addr()
	if !addr.IsValid() || !cidrCluster.IsSingleIP() {
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
		ev.namespace = k8sMeta.Namespace
		ev.podName = k8sMeta.PodName
		ev.hasMeta = true
	}

	select {
	case s.queue <- ev:
	default:
		s.queueWasFull.Store(true)
		s.queue <- ev
	}
}

// run consumes events from the queue until ctx is cancelled.
func (s *source) run(ctx context.Context, health cell.Health) error {
	if health != nil {
		health.OK("Running")
	}
	for {
		select {
		case <-ctx.Done():
			return nil
		case ev := <-s.queue:
			wasFull := s.queueWasFull.Swap(false)
			if wasFull && health != nil {
				health.Degraded("Event queue full; IPCache listener blocked", nil)
			}
			s.handleEvent(ctx, ev)
			if !wasFull && len(s.queue) == 0 && health != nil {
				health.OK("Running")
			}
		}
	}
}

func (s *source) handleEvent(ctx context.Context, ev callbackEvent) {
	switch ev.modType {
	case ipcache.Upsert:
		if ev.hasMeta {
			s.upsertPodIP(ctx, ev)
		} else {
			// A single-IP entry can lose pod metadata during replacement.
			s.evictIP(ev.addr)
		}
	case ipcache.Delete:
		if ev.hasMeta {
			// Ignore stale deletes after pod-to-pod IP reassignment.
			s.evictIPForPod(ev.addr, ev.namespace+"/"+ev.podName)
		} else {
			s.evictIP(ev.addr)
		}
	}
}

// upsertPodIP applies a pod IP add, update, or reassignment.
func (s *source) upsertPodIP(ctx context.Context, ev callbackEvent) {
	podKey := ev.namespace + "/" + ev.podName

	labels, identityOK := s.lookupIdentityLabels(ctx, ev.newID)

	s.mu.Lock()
	defer s.mu.Unlock()

	if prevKey, owned := s.ipToKey[ev.addr]; owned && prevKey != podKey {
		if evicted := s.removeIPLocked(prevKey, ev.addr); evicted != nil {
			s.emit(*evicted)
		}
	}

	ep, exists := s.endpoints[podKey]
	if !identityOK {
		if !exists {
			s.logger.Debug(
				"Skipping pod endpoint upsert: identity not resolvable",
				logfields.Identity, ev.newID,
				logfields.K8sNamespace, ev.namespace,
				logfields.K8sPodName, ev.podName,
			)
			return
		}
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
			Key:    podKey,
			IPs:    []netip.Addr{ev.addr},
			Labels: labels,
			NodeIP: ev.hostIP,
		}
		s.endpoints[podKey] = ep
	} else {
		ep.Labels = labels
		ep.NodeIP = ev.hostIP
		if !slices.Contains(ep.IPs, ev.addr) {
			ep.IPs = append(ep.IPs, ev.addr)
			sortIPs(ep.IPs)
		}
	}
	s.ipToKey[ev.addr] = podKey

	s.emit(Event{Kind: EventKindUpsert, Endpoint: cloneEndpoint(ep)})
}

// evictIP drops an IP from whichever endpoint currently owns it.
func (s *source) evictIP(addr netip.Addr) {
	s.mu.Lock()
	defer s.mu.Unlock()

	prevKey, owned := s.ipToKey[addr]
	if !owned {
		return
	}
	if ev := s.removeIPLocked(prevKey, addr); ev != nil {
		s.emit(*ev)
	}
}

// evictIPForPod drops an IP only if the given pod still owns it.
func (s *source) evictIPForPod(addr netip.Addr, podKey string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	prevKey, owned := s.ipToKey[addr]
	if !owned || prevKey != podKey {
		return
	}
	if ev := s.removeIPLocked(prevKey, addr); ev != nil {
		s.emit(*ev)
	}
}

// removeIPLocked removes addr and returns the event to emit. s.mu must be held.
func (s *source) removeIPLocked(podKey string, addr netip.Addr) *Event {
	delete(s.ipToKey, addr)

	ep, ok := s.endpoints[podKey]
	if !ok {
		return nil
	}
	ep.IPs = slices.DeleteFunc(ep.IPs, func(a netip.Addr) bool { return a == addr })
	if len(ep.IPs) == 0 {
		delete(s.endpoints, podKey)
		return &Event{
			Kind:     EventKindDelete,
			Endpoint: PodEndpoint{Key: podKey},
		}
	}
	return &Event{Kind: EventKindUpsert, Endpoint: cloneEndpoint(ep)}
}

// lookupIdentityLabels resolves an identity ID to identity labels.
func (s *source) lookupIdentityLabels(ctx context.Context, id identity.NumericIdentity) (labels.LabelArray, bool) {
	ident := s.identityAllocator.LookupIdentityByID(ctx, id)
	if ident == nil {
		return nil, false
	}
	return ident.Labels.LabelArray(), true
}

// cloneEndpoint returns an event snapshot detached from source state.
func cloneEndpoint(ep *PodEndpoint) PodEndpoint {
	out := PodEndpoint{
		Key:    ep.Key,
		NodeIP: ep.NodeIP,
		IPs:    slices.Clone(ep.IPs),
		Labels: slices.Clone(ep.Labels),
	}
	return out
}

func sortIPs(ips []netip.Addr) {
	slices.SortFunc(ips, netip.Addr.Compare)
}

// Ensure interface satisfaction at compile time.
var (
	_ ipcache.IPIdentityMappingListener = (*source)(nil)
	_ Source                            = (*source)(nil)
)
