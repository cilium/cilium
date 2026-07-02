// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package podendpointsource

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/cilium/stream"
	"github.com/stretchr/testify/require"

	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/ipcache"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/lock"
	testidentity "github.com/cilium/cilium/pkg/testutils/identity"
)

// newTestSource constructs a source without hive/IPCache/job wiring so that
// unit tests can drive OnIPIdentityCacheChange directly and observe emitted
// events. The caller is responsible for stopping the source via the returned
// cancel func.
func newTestSource(t *testing.T) (s *source, stop func()) {
	t.Helper()

	allocator := testidentity.NewMockIdentityAllocator(nil)
	s = &source{
		logger:            hivetest.Logger(t),
		identityAllocator: allocator,
		queue:             make(chan callbackEvent, queueSize),
		endpoints:         map[string]*PodEndpoint{},
		ipToKey:           map[netip.Addr]string{},
	}
	s.observable, s.emit, s.complete = stream.Multicast[Event]()

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		_ = s.run(ctx, nil)
		close(done)
	}()

	stop = func() {
		cancel()
		<-done
		s.complete(nil)
	}
	return s, stop
}

// allocateIdentity creates an identity in the mock allocator so that the
// source's lookupIdentityLabels can resolve it. Returns the numeric ID.
func allocateIdentity(t *testing.T, s *source, lbls map[string]string) identity.NumericIdentity {
	t.Helper()
	alloc := s.identityAllocator.(*testidentity.MockIdentityAllocator)
	id, _, err := alloc.AllocateIdentity(context.Background(), labels.Map2Labels(lbls, labels.LabelSourceK8s), false, 0)
	require.NoError(t, err)
	return id.ID
}

func requireK8sLabels(t *testing.T, got labels.LabelArray, want map[string]string) {
	t.Helper()
	require.Equal(t, want, got.K8sStringMap())
}

type recordingHealth struct {
	lock.Mutex
	degraded bool
}

func (h *recordingHealth) OK(string) {}

func (h *recordingHealth) Stopped(string) {}

func (h *recordingHealth) Degraded(string, error) {
	h.Lock()
	defer h.Unlock()
	h.degraded = true
}

func (h *recordingHealth) NewScope(string) cell.Health { return h }

func (h *recordingHealth) Close() {}

func (h *recordingHealth) isDegraded() bool {
	h.Lock()
	defer h.Unlock()
	return h.degraded
}

// subscribe returns a channel that receives events emitted by s after the
// call returns. The subscription is cancelled when the test ends.
func subscribe(t *testing.T, s *source) <-chan Event {
	t.Helper()
	ch := make(chan Event, 64)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	done := make(chan struct{})
	go func() {
		s.Observe(ctx, func(ev Event) { ch <- ev }, func(error) { close(done) })
	}()
	return ch
}

// waitForEvent reads one event with a timeout.
func waitForEvent(t *testing.T, ch <-chan Event) Event {
	t.Helper()
	select {
	case ev := <-ch:
		return ev
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for event")
		return Event{}
	}
}

// drainFor drains events from ch until no event arrives for idleFor. This is
// used when a single IPCache change is expected to produce a fixed small
// number of events and we want the entire sequence.
func drainFor(ch <-chan Event, idleFor time.Duration) []Event {
	var out []Event
	for {
		select {
		case ev := <-ch:
			out = append(out, ev)
		case <-time.After(idleFor):
			return out
		}
	}
}

func mustAddr(s string) netip.Addr {
	a, err := netip.ParseAddr(s)
	if err != nil {
		panic(err)
	}
	return a
}

func prefixCluster(addr netip.Addr, bits int, clusterID uint32) cmtypes.PrefixCluster {
	return cmtypes.PrefixClusterFrom(
		netip.PrefixFrom(addr, bits),
		cmtypes.WithClusterID(clusterID),
	)
}

func pushUpsert(s *source, addr netip.Addr, bits int, clusterID uint32,
	id identity.NumericIdentity, namespace, podName string, hostIP string,
) {
	var k8sMeta *ipcache.K8sMetadata
	if namespace != "" || podName != "" {
		k8sMeta = &ipcache.K8sMetadata{Namespace: namespace, PodName: podName}
	}
	var hostIPnet net.IP
	if hostIP != "" {
		hostIPnet = net.ParseIP(hostIP)
	}
	s.OnIPIdentityCacheChange(
		ipcache.Upsert,
		prefixCluster(addr, bits, clusterID),
		nil, hostIPnet,
		nil, ipcache.Identity{ID: id},
		0, k8sMeta, 0,
	)
}

func pushDelete(s *source, addr netip.Addr, bits int, clusterID uint32,
	namespace, podName string,
) {
	var k8sMeta *ipcache.K8sMetadata
	if namespace != "" || podName != "" {
		k8sMeta = &ipcache.K8sMetadata{Namespace: namespace, PodName: podName}
	}
	s.OnIPIdentityCacheChange(
		ipcache.Delete,
		prefixCluster(addr, bits, clusterID),
		nil, nil,
		nil, ipcache.Identity{},
		0, k8sMeta, 0,
	)
}

// TestPrefixFilter verifies that only /32 and /128 entries are accepted.
func TestPrefixFilter(t *testing.T) {
	s, stop := newTestSource(t)
	defer stop()

	id := allocateIdentity(t, s, map[string]string{"app": "test"})
	ch := subscribe(t, s)

	// /24 rejected.
	pushUpsert(s, mustAddr("10.0.0.0"), 24, 0, id, "default", "pod", "192.168.1.1")
	// /64 rejected.
	pushUpsert(s, mustAddr("fd00::"), 64, 0, id, "default", "pod", "192.168.1.1")
	// /32 accepted.
	pushUpsert(s, mustAddr("10.0.0.1"), 32, 0, id, "default", "pod", "192.168.1.1")

	ev := waitForEvent(t, ch)
	require.Equal(t, EventKindUpsert, ev.Kind)
	require.Equal(t, "default/pod", ev.Endpoint.Key)
	require.Equal(t, []netip.Addr{mustAddr("10.0.0.1")}, ev.Endpoint.IPs)

	// No further events should have fired from the rejected prefixes.
	require.Empty(t, drainFor(ch, 100*time.Millisecond))
}

// TestIPv128Accepted verifies that /128 prefixes are accepted.
func TestIPv128Accepted(t *testing.T) {
	s, stop := newTestSource(t)
	defer stop()

	id := allocateIdentity(t, s, map[string]string{"app": "v6"})
	ch := subscribe(t, s)

	pushUpsert(s, mustAddr("fd00::1"), 128, 0, id, "default", "v6pod", "192.168.1.1")

	ev := waitForEvent(t, ch)
	require.Equal(t, EventKindUpsert, ev.Kind)
	require.Equal(t, []netip.Addr{mustAddr("fd00::1")}, ev.Endpoint.IPs)
}

// TestRemoteClusterIgnored verifies that entries from remote clustermesh
// clusters are not processed.
func TestRemoteClusterIgnored(t *testing.T) {
	s, stop := newTestSource(t)
	defer stop()

	id := allocateIdentity(t, s, map[string]string{"app": "remote"})
	ch := subscribe(t, s)

	pushUpsert(s, mustAddr("10.0.0.99"), 32, 2, id, "default", "remote", "192.168.1.1")
	require.Empty(t, drainFor(ch, 100*time.Millisecond))

	// The same IP from the local cluster should still be processed.
	pushUpsert(s, mustAddr("10.0.0.99"), 32, 0, id, "default", "local", "192.168.1.1")
	ev := waitForEvent(t, ch)
	require.Equal(t, "default/local", ev.Endpoint.Key)
}

// TestUpsertAndDelete covers the basic lifecycle of a pod endpoint.
func TestUpsertAndDelete(t *testing.T) {
	s, stop := newTestSource(t)
	defer stop()

	id := allocateIdentity(t, s, map[string]string{"app": "web"})
	ch := subscribe(t, s)

	pushUpsert(s, mustAddr("10.0.0.1"), 32, 0, id, "default", "web", "192.168.1.1")
	ev := waitForEvent(t, ch)
	require.Equal(t, EventKindUpsert, ev.Kind)
	require.Equal(t, "default/web", ev.Endpoint.Key)
	requireK8sLabels(t, ev.Endpoint.Labels, map[string]string{"app": "web"})
	require.Equal(t, "192.168.1.1", ev.Endpoint.NodeIP)

	pushDelete(s, mustAddr("10.0.0.1"), 32, 0, "default", "web")
	ev = waitForEvent(t, ch)
	require.Equal(t, EventKindDelete, ev.Kind)
	require.Equal(t, "default/web", ev.Endpoint.Key)
}

// TestIPOrdering verifies IPs are sorted IPv4-first then numeric within each
// family, regardless of insertion order.
func TestIPOrdering(t *testing.T) {
	s, stop := newTestSource(t)
	defer stop()

	id := allocateIdentity(t, s, map[string]string{"app": "dual"})
	ch := subscribe(t, s)

	// Push an IPv6 first, then two IPv4s out of numeric order.
	pushUpsert(s, mustAddr("fd00::10"), 128, 0, id, "default", "dual", "192.168.1.1")
	<-ch
	pushUpsert(s, mustAddr("10.0.0.2"), 32, 0, id, "default", "dual", "192.168.1.1")
	<-ch
	pushUpsert(s, mustAddr("10.0.0.1"), 32, 0, id, "default", "dual", "192.168.1.1")
	ev := waitForEvent(t, ch)

	require.Equal(t, []netip.Addr{
		mustAddr("10.0.0.1"),
		mustAddr("10.0.0.2"),
		mustAddr("fd00::10"),
	}, ev.Endpoint.IPs)
}

// TestIPReassignmentBetweenPods covers the O2 leak scenario where an IP is
// reclaimed by a different pod before the original pod's Delete arrives,
// and additionally verifies that a subsequently-arriving stale Delete for
// the original pod does not clobber the new pod.
func TestIPReassignmentBetweenPods(t *testing.T) {
	s, stop := newTestSource(t)
	defer stop()

	idA := allocateIdentity(t, s, map[string]string{"app": "a"})
	idB := allocateIdentity(t, s, map[string]string{"app": "b"})
	ch := subscribe(t, s)

	addr := mustAddr("10.0.0.5")

	pushUpsert(s, addr, 32, 0, idA, "default", "pod-a", "192.168.1.1")
	ev := waitForEvent(t, ch)
	require.Equal(t, "default/pod-a", ev.Endpoint.Key)

	// Reassign the same IP before the old Delete arrives.
	pushUpsert(s, addr, 32, 0, idB, "default", "pod-b", "192.168.1.1")
	events := drainFor(ch, 200*time.Millisecond)
	require.Len(t, events, 2, "expected eviction + upsert, got %v", events)

	require.Equal(t, EventKindDelete, events[0].Kind)
	require.Equal(t, "default/pod-a", events[0].Endpoint.Key)

	require.Equal(t, EventKindUpsert, events[1].Kind)
	require.Equal(t, "default/pod-b", events[1].Endpoint.Key)
	require.Equal(t, []netip.Addr{addr}, events[1].Endpoint.IPs)

	// Stale Delete for pod-a must not evict the current owner.
	pushDelete(s, addr, 32, 0, "default", "pod-a")
	require.Empty(t, drainFor(ch, 200*time.Millisecond),
		"stale delete for pod-a must not evict pod-b or emit any event")

	s.mu.RLock()
	remaining, ok := s.endpoints["default/pod-b"]
	owner, owned := s.ipToKey[addr]
	s.mu.RUnlock()
	require.True(t, ok, "pod-b must still exist after stale delete for pod-a")
	require.Equal(t, []netip.Addr{addr}, remaining.IPs)
	require.True(t, owned)
	require.Equal(t, "default/pod-b", owner)
}

// TestDeleteOwnershipCheckForUnrelatedPod is the direct regression test for
// the stale-Delete ownership bug: IPCache emits a Delete whose oldK8sMeta
// identifies a pod that no longer owns the IP, and the source must ignore
// it.
func TestDeleteOwnershipCheckForUnrelatedPod(t *testing.T) {
	s, stop := newTestSource(t)
	defer stop()

	id := allocateIdentity(t, s, map[string]string{"app": "owner"})
	ch := subscribe(t, s)

	addr := mustAddr("10.0.0.42")
	pushUpsert(s, addr, 32, 0, id, "ns", "owner", "192.168.1.1")
	ev := waitForEvent(t, ch)
	require.Equal(t, "ns/owner", ev.Endpoint.Key)

	// Delete for an unrelated pod must not affect the current owner.
	pushDelete(s, addr, 32, 0, "other-ns", "ghost")
	require.Empty(t, drainFor(ch, 150*time.Millisecond),
		"delete targeted at an unrelated pod must be a no-op")

	s.mu.RLock()
	_, stillThere := s.endpoints["ns/owner"]
	owner := s.ipToKey[addr]
	s.mu.RUnlock()
	require.True(t, stillThere)
	require.Equal(t, "ns/owner", owner)

	// A correctly-targeted Delete still evicts the pod.
	pushDelete(s, addr, 32, 0, "ns", "owner")
	ev = waitForEvent(t, ch)
	require.Equal(t, EventKindDelete, ev.Kind)
	require.Equal(t, "ns/owner", ev.Endpoint.Key)
}

// TestUpsertWithoutMetaEvictsExistingIP covers a single-IP entry that loses
// pod metadata.
func TestUpsertWithoutMetaEvictsExistingIP(t *testing.T) {
	s, stop := newTestSource(t)
	defer stop()

	id := allocateIdentity(t, s, map[string]string{"app": "x"})
	ch := subscribe(t, s)

	addr := mustAddr("10.0.0.7")
	pushUpsert(s, addr, 32, 0, id, "default", "pod-x", "192.168.1.1")
	<-ch

	// The same single-IP entry is re-upserted without pod metadata.
	pushUpsert(s, addr, 32, 0, identity.ReservedIdentityWorld, "", "", "")
	ev := waitForEvent(t, ch)
	require.Equal(t, EventKindDelete, ev.Kind)
	require.Equal(t, "default/pod-x", ev.Endpoint.Key)

	// The source's internal mirror must agree.
	s.mu.RLock()
	_, exists := s.endpoints["default/pod-x"]
	_, owned := s.ipToKey[addr]
	s.mu.RUnlock()
	require.False(t, exists)
	require.False(t, owned)
}

// TestMultipleIPsPartialDelete checks that deleting one of two IPs from an
// endpoint emits an Upsert (not a Delete) with the remaining IP.
func TestMultipleIPsPartialDelete(t *testing.T) {
	s, stop := newTestSource(t)
	defer stop()

	id := allocateIdentity(t, s, map[string]string{"app": "multi"})
	ch := subscribe(t, s)

	v4 := mustAddr("10.0.0.8")
	v6 := mustAddr("fd00::8")

	pushUpsert(s, v4, 32, 0, id, "default", "multi", "192.168.1.1")
	<-ch
	pushUpsert(s, v6, 128, 0, id, "default", "multi", "192.168.1.1")
	<-ch

	pushDelete(s, v4, 32, 0, "default", "multi")
	ev := waitForEvent(t, ch)
	require.Equal(t, EventKindUpsert, ev.Kind)
	require.Equal(t, []netip.Addr{v6}, ev.Endpoint.IPs)

	pushDelete(s, v6, 128, 0, "default", "multi")
	ev = waitForEvent(t, ch)
	require.Equal(t, EventKindDelete, ev.Kind)
}

// TestNilIdentityOnExistingEndpointPreservesLabels covers T2: when a later
// Upsert arrives with an identity that cannot be resolved, the endpoint's
// existing labels are preserved rather than being wiped.
func TestNilIdentityOnExistingEndpointPreservesLabels(t *testing.T) {
	s, stop := newTestSource(t)
	defer stop()

	id := allocateIdentity(t, s, map[string]string{"app": "stable"})
	ch := subscribe(t, s)

	addr := mustAddr("10.0.0.9")
	pushUpsert(s, addr, 32, 0, id, "default", "stable", "192.168.1.1")
	ev := waitForEvent(t, ch)
	requireK8sLabels(t, ev.Endpoint.Labels, map[string]string{"app": "stable"})

	// Push an Upsert for a numeric identity that was never allocated;
	// the mock allocator returns nil for unknown IDs.
	unresolved := identity.NumericIdentity(9_999_999)
	pushUpsert(s, addr, 32, 0, unresolved, "default", "stable", "192.168.2.2")
	ev = waitForEvent(t, ch)
	requireK8sLabels(t, ev.Endpoint.Labels, map[string]string{"app": "stable"})
	require.Equal(t, "192.168.2.2", ev.Endpoint.NodeIP)
}

// TestNilIdentityOnNewEndpointIsSkipped verifies that an Upsert for a pod
// we have not seen before, with an unresolvable identity, is dropped rather
// than creating a degenerate entry.
func TestNilIdentityOnNewEndpointIsSkipped(t *testing.T) {
	s, stop := newTestSource(t)
	defer stop()

	ch := subscribe(t, s)

	unresolved := identity.NumericIdentity(9_999_999)
	pushUpsert(s, mustAddr("10.0.0.10"), 32, 0, unresolved, "default", "ghost", "192.168.1.1")
	require.Empty(t, drainFor(ch, 100*time.Millisecond))

	s.mu.RLock()
	_, exists := s.endpoints["default/ghost"]
	s.mu.RUnlock()
	require.False(t, exists)
}

// TestObserveReplaysCurrentState verifies that a subscriber joining after
// some upserts have been processed receives them as Upsert events on
// subscription.
func TestObserveReplaysCurrentState(t *testing.T) {
	s, stop := newTestSource(t)
	defer stop()

	id := allocateIdentity(t, s, map[string]string{"app": "r"})

	pushUpsert(s, mustAddr("10.0.0.20"), 32, 0, id, "default", "r1", "192.168.1.1")
	pushUpsert(s, mustAddr("10.0.0.21"), 32, 0, id, "default", "r2", "192.168.1.1")

	// Give the consumer time to process both events before subscribing.
	require.Eventually(t, func() bool {
		s.mu.RLock()
		defer s.mu.RUnlock()
		return len(s.endpoints) == 2
	}, time.Second, 10*time.Millisecond)

	ch := subscribe(t, s)
	events := drainFor(ch, 200*time.Millisecond)
	require.Len(t, events, 2)

	ids := map[string]bool{}
	for _, ev := range events {
		require.Equal(t, EventKindUpsert, ev.Kind)
		ids[ev.Endpoint.Key] = true
	}
	require.True(t, ids["default/r1"])
	require.True(t, ids["default/r2"])
}

func TestQueueFullReportsHealth(t *testing.T) {
	s := &source{
		queue:     make(chan callbackEvent, 1),
		endpoints: map[string]*PodEndpoint{},
		ipToKey:   map[netip.Addr]string{},
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	health := &recordingHealth{}
	done := make(chan error, 1)
	go func() {
		done <- s.run(ctx, health)
	}()

	s.queueWasFull.Store(true)
	s.queue <- callbackEvent{modType: ipcache.Delete, addr: mustAddr("10.0.0.1")}

	require.Eventually(t, health.isDegraded, time.Second, 10*time.Millisecond)
	cancel()
	require.NoError(t, <-done)
}

// TestConcurrentIPCacheEvents stresses the queue path with many concurrent
// OnIPIdentityCacheChange callers and verifies that the consumer drains
// them all without data races. Run with `go test -race`.
func TestConcurrentIPCacheEvents(t *testing.T) {
	s, stop := newTestSource(t)
	defer stop()

	id := allocateIdentity(t, s, map[string]string{"app": "stress"})

	const pods = 50
	var wg sync.WaitGroup
	for i := range pods {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			addr := netip.AddrFrom4([4]byte{10, 0, byte(i >> 8), byte(i)})
			pushUpsert(s, addr, 32, 0, id, "default", "pod", "192.168.1.1")
			pushDelete(s, addr, 32, 0, "default", "pod")
		}(i)
	}
	wg.Wait()

	// Every pod shares the same name so the final state is either
	// "pod" with no IPs (so the entry is gone) or with some subset of
	// IPs, but never panics.
	require.Eventually(t, func() bool {
		s.mu.RLock()
		defer s.mu.RUnlock()
		return len(s.queue) == 0
	}, 2*time.Second, 10*time.Millisecond)
}

// TestCloneEndpointIsolatesSubscribers ensures that mutating the labels or
// IPs of a received event does not corrupt the source's internal state.
func TestCloneEndpointIsolatesSubscribers(t *testing.T) {
	s, stop := newTestSource(t)
	defer stop()

	id := allocateIdentity(t, s, map[string]string{"app": "iso"})
	ch := subscribe(t, s)

	pushUpsert(s, mustAddr("10.0.0.50"), 32, 0, id, "default", "iso", "192.168.1.1")
	ev := waitForEvent(t, ch)

	// Mutate the received event payload.
	ev.Endpoint.Labels[0] = labels.NewLabel("evil", "mutation", labels.LabelSourceK8s)
	ev.Endpoint.IPs[0] = mustAddr("127.0.0.1")

	// Internal state must be unaffected.
	s.mu.RLock()
	internal := s.endpoints["default/iso"]
	s.mu.RUnlock()
	require.NotContains(t, internal.Labels.K8sStringMap(), "evil")
	require.Equal(t, mustAddr("10.0.0.50"), internal.IPs[0])
}
