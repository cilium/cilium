// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package nodes

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/cidr"
	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/hubble/parser/getters"
	"github.com/cilium/cilium/pkg/identity"
	iputil "github.com/cilium/cilium/pkg/ip"
	"github.com/cilium/cilium/pkg/ipcache"
	"github.com/cilium/cilium/pkg/node/addressing"
	"github.com/cilium/cilium/pkg/node/manager"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/source"
)

const (
	localClusterID  = uint32(10)
	remoteClusterID = uint32(42)
	localCluster    = "local"
	remoteCluster   = "remote"
)

type fakeNodeStateNotifier struct {
	mu               sync.Mutex
	initial          []nodeTypes.Node
	observer         manager.NodeStateObserver
	subscribeCalls   int
	unsubscribeCalls int
}

type blockingNodeStateNotifier struct {
	*fakeNodeStateNotifier
	subscribeEntered chan struct{}
	releaseSubscribe chan struct{}
}

func (f *blockingNodeStateNotifier) SubscribeNodeState(observer manager.NodeStateObserver) {
	close(f.subscribeEntered)
	<-f.releaseSubscribe
	f.fakeNodeStateNotifier.SubscribeNodeState(observer)
}

func (f *fakeNodeStateNotifier) SubscribeNodeState(observer manager.NodeStateObserver) {
	f.mu.Lock()
	f.subscribeCalls++
	f.observer = observer
	initial := append([]nodeTypes.Node(nil), f.initial...)
	f.mu.Unlock()
	for _, n := range initial {
		observer.NodeUpsert(n)
	}
}

func (f *fakeNodeStateNotifier) UnsubscribeNodeState(observer manager.NodeStateObserver) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.unsubscribeCalls++
	if f.observer == observer {
		f.observer = nil
	}
}

func (f *fakeNodeStateNotifier) calls() (subscribe, unsubscribe int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.subscribeCalls, f.unsubscribeCalls
}

func newTestIPCache(t testing.TB) *ipcache.IPCache {
	t.Helper()
	ipc := ipcache.NewIPCache(&ipcache.Configuration{
		Context: context.Background(),
		Logger:  hivetest.Logger(t),
	})
	t.Cleanup(func() { require.NoError(t, ipc.Shutdown()) })
	return ipc
}

func upsertHost(t testing.TB, ipc *ipcache.IPCache, endpoint, host string) {
	t.Helper()
	_, err := ipc.Upsert(endpoint, net.ParseIP(host), 0, nil, ipcache.Identity{
		ID:     identity.GetMinimalAllocationIdentity(0),
		Source: source.KVStore,
	})
	require.NoError(t, err)
}

func nodeWithAddresses(cluster, name string, clusterID uint32, nodeLabels map[string]string, addresses ...string) nodeTypes.Node {
	n := nodeTypes.Node{
		Name:      name,
		Cluster:   cluster,
		ClusterID: clusterID,
		Labels:    nodeLabels,
	}
	for _, address := range addresses {
		n.IPAddresses = append(n.IPAddresses, nodeTypes.Address{
			Type: addressing.NodeInternalIP,
			IP:   net.ParseIP(address),
		})
	}
	return n
}

func allocatedHint(clusterID uint32) getters.NodeClusterHint {
	return getters.NodeClusterHint{
		Identity:      identity.GetMinimalAllocationIdentity(clusterID),
		IdentityKnown: true,
	}
}

func requireLabels(t testing.TB, want []string, got []string, msgAndArgs ...any) {
	t.Helper()
	require.Equal(t, want, got, msgAndArgs...)
}

func TestResolverLifecycleStartReplaysSynchronouslyAndIsIdempotent(t *testing.T) {
	ipc := newTestIPCache(t)
	notifier := &fakeNodeStateNotifier{initial: []nodeTypes.Node{
		nodeWithAddresses(localCluster, "node-a", localClusterID,
			map[string]string{"z": "last", "a": "first"}, "192.0.2.10"),
	}}
	r := NewResolver(ipc, cmtypes.ClusterInfo{ID: localClusterID, Name: localCluster}, notifier)

	subscribe, unsubscribe := notifier.calls()
	require.Zero(t, subscribe, "construction must not own lifecycle subscription")
	require.Zero(t, unsubscribe)
	require.Empty(t, r.GetNodeLabels(netip.MustParseAddr("192.0.2.10"), allocatedHint(localClusterID)))

	require.NoError(t, r.Start())
	subscribe, unsubscribe = notifier.calls()
	require.Equal(t, 1, subscribe)
	require.Zero(t, unsubscribe)
	requireLabels(t, []string{"a=first", "z=last"},
		r.GetNodeLabels(netip.MustParseAddr("192.0.2.10"), allocatedHint(localClusterID)),
		"the notifier replay must complete before Start returns")

	require.NoError(t, r.Start())
	r.Stop()
	r.Stop()
	subscribe, unsubscribe = notifier.calls()
	require.Equal(t, 1, subscribe, "repeated Start must not subscribe twice")
	require.Equal(t, 1, unsubscribe, "repeated Stop must not unsubscribe twice")
}

func TestResolverLifecycleFailsClosedWithoutNotifierAndAfterStop(t *testing.T) {
	r := NewResolver(nil, cmtypes.ClusterInfo{ID: localClusterID, Name: localCluster}, nil)
	require.ErrorContains(t, r.Start(), "notifier")
	r.Stop()
	require.ErrorContains(t, r.Start(), "stopped")

	notifier := &fakeNodeStateNotifier{}
	r = NewResolver(nil, cmtypes.ClusterInfo{ID: localClusterID, Name: localCluster}, notifier)
	require.NoError(t, r.Start())
	r.Stop()
	require.ErrorContains(t, r.Start(), "stopped")
	subscribe, unsubscribe := notifier.calls()
	require.Equal(t, 1, subscribe)
	require.Equal(t, 1, unsubscribe)
}

func TestResolverLifecycleSerializesConcurrentStartAndStop(t *testing.T) {
	notifier := &blockingNodeStateNotifier{
		fakeNodeStateNotifier: &fakeNodeStateNotifier{},
		subscribeEntered:      make(chan struct{}),
		releaseSubscribe:      make(chan struct{}),
	}
	r := NewResolver(nil, cmtypes.ClusterInfo{ID: localClusterID, Name: localCluster}, notifier)

	startResults := make(chan error, 2)
	go func() { startResults <- r.Start() }()
	<-notifier.subscribeEntered
	go func() { startResults <- r.Start() }()
	close(notifier.releaseSubscribe)
	require.NoError(t, <-startResults)
	require.NoError(t, <-startResults)

	var stops sync.WaitGroup
	stops.Add(2)
	go func() {
		defer stops.Done()
		r.Stop()
	}()
	go func() {
		defer stops.Done()
		r.Stop()
	}()
	stops.Wait()

	subscribe, unsubscribe := notifier.calls()
	require.Equal(t, 1, subscribe)
	require.Equal(t, 1, unsubscribe)
}

func TestResolverSelectsAuthoritativeIdentityScope(t *testing.T) {
	ipc := newTestIPCache(t)
	r := NewResolver(ipc, cmtypes.ClusterInfo{ID: localClusterID, Name: localCluster}, nil)
	r.NodeUpsert(nodeWithAddresses(localCluster, "local-node", localClusterID,
		map[string]string{"cluster": localCluster}, "192.0.2.10"))
	r.NodeUpsert(nodeWithAddresses(remoteCluster, "remote-node", remoteClusterID,
		map[string]string{"cluster": remoteCluster}, "192.0.2.42"))

	// The endpoint IP overlaps, so only exact IPCache scope can distinguish it.
	upsertHost(t, ipc, "10.0.0.1", "192.0.2.10")
	upsertHost(t, ipc, "10.0.0.1@42", "192.0.2.42")

	for _, id := range []identity.NumericIdentity{
		identity.GetMinimalAllocationIdentity(localClusterID),
		identity.GetMaximumAllocationIdentity(localClusterID),
	} {
		requireLabels(t, []string{"cluster=local"}, r.GetNodeLabels(
			netip.MustParseAddr("10.0.0.1"),
			getters.NodeClusterHint{Identity: id, IdentityKnown: true},
		))
	}
	for _, id := range []identity.NumericIdentity{
		identity.GetMinimalAllocationIdentity(remoteClusterID),
		identity.GetMaximumAllocationIdentity(remoteClusterID),
	} {
		requireLabels(t, []string{"cluster=remote"}, r.GetNodeLabels(
			netip.MustParseAddr("10.0.0.1"),
			getters.NodeClusterHint{Identity: id, IdentityKnown: true},
		))
	}

	requireLabels(t, []string{"cluster=local"}, r.GetNodeLabels(
		netip.MustParseAddr("10.0.0.1"),
		getters.NodeClusterHint{Identity: identity.ReservedIdentityHost, IdentityKnown: true},
	))
	require.Empty(t, r.GetNodeLabels(netip.MustParseAddr("10.0.0.1"), getters.NodeClusterHint{
		Identity: identity.GetMinimalAllocationIdentity(remoteClusterID), IdentityKnown: false,
	}))
	require.Empty(t, r.GetNodeLabels(netip.Addr{}, allocatedHint(localClusterID)))
}

func TestResolverExplicitLocalHint(t *testing.T) {
	ipc := newTestIPCache(t)
	r := NewResolver(ipc, cmtypes.ClusterInfo{ID: localClusterID, Name: localCluster}, nil)
	r.NodeUpsert(nodeWithAddresses(localCluster, "local-node", localClusterID,
		map[string]string{"scope": "local"}, "192.0.2.10"))
	upsertHost(t, ipc, "10.0.0.1", "192.0.2.10")

	requireLabels(t, []string{"scope=local"}, r.GetNodeLabels(
		netip.MustParseAddr("10.0.0.1"),
		getters.NodeClusterHint{LocalEndpoint: true},
	))
	requireLabels(t, []string{"scope=local"}, r.GetNodeLabels(
		netip.MustParseAddr("10.0.0.1"),
		getters.NodeClusterHint{
			Identity: identity.GetMinimalAllocationIdentity(localClusterID), IdentityKnown: true, LocalEndpoint: true,
		},
	))
	requireLabels(t, []string{"scope=local"}, r.GetNodeLabels(
		netip.MustParseAddr("10.0.0.1"),
		getters.NodeClusterHint{Identity: identity.ReservedIdentityHealth, IdentityKnown: true, LocalEndpoint: true},
	))

	// Event-established locality and an authoritative remote identity contradict.
	require.Empty(t, r.GetNodeLabels(netip.MustParseAddr("10.0.0.1"), getters.NodeClusterHint{
		Identity: identity.GetMinimalAllocationIdentity(remoteClusterID), IdentityKnown: true, LocalEndpoint: true,
	}))
}

func TestResolverRejectsUntrustedIdentityScopes(t *testing.T) {
	ipc := newTestIPCache(t)
	r := NewResolver(ipc, cmtypes.ClusterInfo{ID: localClusterID, Name: localCluster}, nil)
	r.NodeUpsert(nodeWithAddresses(localCluster, "local-node", localClusterID,
		map[string]string{"scope": "local"}, "192.0.2.10"))
	upsertHost(t, ipc, "10.0.0.1", "192.0.2.10")

	malformedGlobal := identity.UserReservedNumericIdentity - 1
	require.Less(t, malformedGlobal, identity.GetMinimalAllocationIdentity(0))
	require.False(t, malformedGlobal.IsReservedIdentity())
	require.False(t, identity.IsUserReservedIdentity(malformedGlobal))
	require.Equal(t, identity.IdentityScopeGlobal, malformedGlobal.Scope())
	require.False(t, malformedGlobal.HasLocalScope())
	require.False(t, malformedGlobal.HasRemoteNodeScope())
	t.Run("below allocation range", func(t *testing.T) {
		ipc := newTestIPCache(t)
		r := NewResolver(ipc, cmtypes.ClusterInfo{ID: 0, Name: localCluster}, nil)
		r.NodeUpsert(nodeWithAddresses(localCluster, "local-node", 0,
			map[string]string{"scope": "local-zero"}, "192.0.2.127"))
		upsertHost(t, ipc, "10.0.0.127", "192.0.2.127")

		require.Empty(t, r.GetNodeLabels(netip.MustParseAddr("10.0.0.127"), getters.NodeClusterHint{
			Identity: malformedGlobal, IdentityKnown: true,
		}))
	})

	maxGlobal := identity.GetMaximumAllocationIdentity(cmtypes.ClusterIDMax)
	cases := map[string]identity.NumericIdentity{
		"unknown":                   identity.IdentityUnknown,
		"world":                     identity.ReservedIdentityWorld,
		"user reserved":             identity.UserReservedNumericIdentity,
		"above allocation range":    maxGlobal + 1,
		"local scope":               identity.MinLocalIdentity,
		"health":                    identity.ReservedIdentityHealth,
		"ingress":                   identity.ReservedIdentityIngress,
		"remote node":               identity.ReservedIdentityRemoteNode,
		"kube apiserver":            identity.ReservedIdentityKubeAPIServer,
		"dynamic remote-node scope": identity.IdentityScopeRemoteNode | identity.GetMinimalAllocationIdentity(remoteClusterID),
	}
	for name, id := range cases {
		t.Run(name, func(t *testing.T) {
			require.Empty(t, r.GetNodeLabels(netip.MustParseAddr("10.0.0.1"), getters.NodeClusterHint{
				Identity: id, IdentityKnown: true,
			}))
		})
	}

	// A userspace-filled identity is not authoritative, regardless of its value.
	require.Empty(t, r.GetNodeLabels(netip.MustParseAddr("10.0.0.1"), getters.NodeClusterHint{
		Identity: identity.GetMinimalAllocationIdentity(localClusterID),
	}))
}

func TestResolverIPv4IPv6AndSameNodeBothDirections(t *testing.T) {
	ipc := newTestIPCache(t)
	r := NewResolver(ipc, cmtypes.ClusterInfo{ID: localClusterID, Name: localCluster}, nil)
	r.NodeUpsert(nodeWithAddresses(localCluster, "dual-stack", localClusterID,
		map[string]string{"node": "dual-stack"}, "192.0.2.10", "2001:db8::10"))
	upsertHost(t, ipc, "10.0.0.1", "192.0.2.10")
	upsertHost(t, ipc, "fd00::1", "2001:db8::10")

	sourceLabels := r.GetNodeLabels(netip.MustParseAddr("10.0.0.1"), allocatedHint(localClusterID))
	destinationLabels := r.GetNodeLabels(netip.MustParseAddr("fd00::1"), allocatedHint(localClusterID))
	requireLabels(t, []string{"node=dual-stack"}, sourceLabels)
	requireLabels(t, sourceLabels, destinationLabels)
}

func TestResolverDirectNodeFallbackIsScopedAndUnambiguous(t *testing.T) {
	t.Run("missing IPCache fails closed", func(t *testing.T) {
		r := NewResolver(nil, cmtypes.ClusterInfo{ID: localClusterID, Name: localCluster}, nil)
		r.NodeUpsert(nodeWithAddresses(localCluster, "local-node", localClusterID,
			map[string]string{"node": "local"}, "192.0.2.10"))

		require.Empty(t, r.GetNodeLabels(
			netip.MustParseAddr("192.0.2.10"), allocatedHint(localClusterID)))
	})

	t.Run("local and remote direct node addresses use expected ClusterID", func(t *testing.T) {
		ipc := newTestIPCache(t)
		r := NewResolver(ipc, cmtypes.ClusterInfo{ID: localClusterID, Name: localCluster}, nil)
		r.NodeUpsert(nodeWithAddresses(localCluster, "local-node", localClusterID,
			map[string]string{"node": "local"}, "192.0.2.10"))
		r.NodeUpsert(nodeWithAddresses(remoteCluster, "remote-node", remoteClusterID,
			map[string]string{"node": "remote"}, "192.0.2.42"))

		requireLabels(t, []string{"node=local"}, r.GetNodeLabels(
			netip.MustParseAddr("192.0.2.10"), allocatedHint(localClusterID)))
		requireLabels(t, []string{"node=remote"}, r.GetNodeLabels(
			netip.MustParseAddr("192.0.2.42"), allocatedHint(remoteClusterID)))
		require.Empty(t, r.GetNodeLabels(
			netip.MustParseAddr("192.0.2.10"), allocatedHint(remoteClusterID)))
	})

	t.Run("owners from other clusters do not make an expected cluster ambiguous", func(t *testing.T) {
		ipc := newTestIPCache(t)
		r := NewResolver(ipc, cmtypes.ClusterInfo{ID: localClusterID, Name: localCluster}, nil)
		r.NodeUpsert(nodeWithAddresses(localCluster, "local-node", localClusterID,
			map[string]string{"node": "local"}, "192.0.2.50"))
		r.NodeUpsert(nodeWithAddresses(remoteCluster, "remote-node", remoteClusterID,
			map[string]string{"node": "remote"}, "192.0.2.50"))

		requireLabels(t, []string{"node=local"}, r.GetNodeLabels(
			netip.MustParseAddr("192.0.2.50"), allocatedHint(localClusterID)))
		requireLabels(t, []string{"node=remote"}, r.GetNodeLabels(
			netip.MustParseAddr("192.0.2.50"), allocatedHint(remoteClusterID)))
	})

	t.Run("two matching owners are ambiguous", func(t *testing.T) {
		ipc := newTestIPCache(t)
		r := NewResolver(ipc, cmtypes.ClusterInfo{ID: localClusterID, Name: localCluster}, nil)
		r.NodeUpsert(nodeWithAddresses(localCluster, "node-a", localClusterID,
			map[string]string{"node": "a"}, "192.0.2.10"))
		r.NodeUpsert(nodeWithAddresses(localCluster, "node-b", localClusterID,
			map[string]string{"node": "b"}, "192.0.2.10"))

		require.Empty(t, r.GetNodeLabels(
			netip.MustParseAddr("192.0.2.10"), allocatedHint(localClusterID)))
	})

	t.Run("IPCache owner miss does not fall back to endpoint", func(t *testing.T) {
		ipc := newTestIPCache(t)
		r := NewResolver(ipc, cmtypes.ClusterInfo{ID: localClusterID, Name: localCluster}, nil)
		r.NodeUpsert(nodeWithAddresses(localCluster, "node-a", localClusterID,
			map[string]string{"node": "a"}, "10.0.0.1"))
		upsertHost(t, ipc, "10.0.0.1", "192.0.2.99")

		require.Empty(t, r.GetNodeLabels(
			netip.MustParseAddr("10.0.0.1"), allocatedHint(localClusterID)))
	})

	for _, tt := range []struct {
		name    string
		entries map[string]net.IP
	}{
		{
			name: "conflicting exact IPCache representations",
			entries: map[string]net.IP{
				"10.0.0.1":    net.ParseIP("192.0.2.10"),
				"10.0.0.1/32": net.ParseIP("192.0.2.11"),
			},
		},
		{
			name: "missing host metadata",
			entries: map[string]net.IP{
				"10.0.0.1": nil,
			},
		},
		{
			name: "invalid host bytes",
			entries: map[string]net.IP{
				"10.0.0.1": {1, 2, 3},
			},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			ipc := newTestIPCache(t)
			r := NewResolver(ipc, cmtypes.ClusterInfo{ID: localClusterID, Name: localCluster}, nil)
			r.NodeUpsert(nodeWithAddresses(localCluster, "endpoint-owner", localClusterID,
				map[string]string{"node": "endpoint-owner"}, "10.0.0.1"))
			for endpoint, hostIP := range tt.entries {
				_, err := ipc.Upsert(endpoint, hostIP, 0, nil, ipcache.Identity{
					ID:     identity.GetMinimalAllocationIdentity(0),
					Source: source.KVStore,
				})
				require.NoError(t, err)
			}

			require.Empty(t, r.GetNodeLabels(
				netip.MustParseAddr("10.0.0.1"), allocatedHint(localClusterID)))
		})
	}
}

func TestResolverOwnerClassificationFailsClosed(t *testing.T) {
	t.Run("configured local ClusterID zero excludes differently named zero", func(t *testing.T) {
		ipc := newTestIPCache(t)
		r := NewResolver(ipc, cmtypes.ClusterInfo{ID: 0, Name: localCluster}, nil)
		r.NodeUpsert(nodeWithAddresses(localCluster, "local", 0,
			map[string]string{"node": "local"}, "192.0.2.10"))
		r.NodeUpsert(nodeWithAddresses(remoteCluster, "remote", 0,
			map[string]string{"node": "remote"}, "192.0.2.10"))

		requireLabels(t, []string{"node=local"}, r.GetNodeLabels(
			netip.MustParseAddr("192.0.2.10"), getters.NodeClusterHint{LocalEndpoint: true}))
	})

	t.Run("remote cluster colliding with local ClusterID is excluded", func(t *testing.T) {
		ipc := newTestIPCache(t)
		r := NewResolver(ipc, cmtypes.ClusterInfo{ID: localClusterID, Name: localCluster}, nil)
		r.NodeUpsert(nodeWithAddresses(remoteCluster, "collision", localClusterID,
			map[string]string{"node": "collision"}, "192.0.2.10"))
		require.Empty(t, r.GetNodeLabels(
			netip.MustParseAddr("192.0.2.10"), allocatedHint(localClusterID)))
	})

	t.Run("local name with contradictory ClusterID is excluded", func(t *testing.T) {
		ipc := newTestIPCache(t)
		r := NewResolver(ipc, cmtypes.ClusterInfo{ID: localClusterID, Name: localCluster}, nil)
		r.NodeUpsert(nodeWithAddresses(localCluster, "contradiction", remoteClusterID,
			map[string]string{"node": "contradiction"}, "192.0.2.42"))
		require.Empty(t, r.GetNodeLabels(
			netip.MustParseAddr("192.0.2.42"), allocatedHint(remoteClusterID)))
		require.Empty(t, r.GetNodeLabels(
			netip.MustParseAddr("192.0.2.42"), allocatedHint(localClusterID)))
		require.Empty(t, r.GetNodeLabels(
			netip.MustParseAddr("192.0.2.42"), getters.NodeClusterHint{LocalEndpoint: true}))
	})

	t.Run("empty remote cluster name is excluded", func(t *testing.T) {
		ipc := newTestIPCache(t)
		r := NewResolver(ipc, cmtypes.ClusterInfo{ID: localClusterID, Name: localCluster}, nil)
		r.NodeUpsert(nodeWithAddresses("", "remote", remoteClusterID,
			map[string]string{"node": "remote"}, "192.0.2.42"))
		require.Empty(t, r.GetNodeLabels(
			netip.MustParseAddr("192.0.2.42"), allocatedHint(remoteClusterID)))
	})
}

func TestResolverUpsertDeleteAndImmutableSnapshots(t *testing.T) {
	ipc := newTestIPCache(t)
	r := NewResolver(ipc, cmtypes.ClusterInfo{ID: localClusterID, Name: localCluster}, nil)

	original := nodeWithAddresses(localCluster, "node-a", 0,
		map[string]string{"version": "one", "a": "first"}, "192.0.2.10", "192.0.2.10")
	original.IPAddresses = append(original.IPAddresses, nodeTypes.Address{
		Type: addressing.NodeExternalIP,
		IP:   net.IP{1, 2, 3}, // invalid and therefore not indexed
	})
	original.IPv4HealthIP = iputil.AddrFrom(netip.MustParseAddr("192.0.2.11"))
	original.IPv6HealthIP = iputil.AddrFrom(netip.MustParseAddr("2001:db8::11"))
	original.IPv4IngressIP = net.ParseIP("192.0.2.12")
	original.IPv6IngressIP = net.ParseIP("2001:db8::12")
	original.IPv4AllocCIDR = cidr.MustParseCIDR("10.244.0.0/24")
	r.NodeUpsert(original)
	original.Labels["version"] = "mutated"
	original.Labels["later"] = "input-map-change"

	oldLabels := r.GetNodeLabels(netip.MustParseAddr("192.0.2.10"), allocatedHint(localClusterID))
	requireLabels(t, []string{"a=first", "version=one"}, oldLabels)
	repeatedLabels := r.GetNodeLabels(netip.MustParseAddr("192.0.2.10"), allocatedHint(localClusterID))
	require.True(t, &oldLabels[0] == &repeatedLabels[0], "cache hits must share the immutable published slice")
	for _, address := range []string{"192.0.2.11", "2001:db8::11", "192.0.2.12", "2001:db8::12"} {
		requireLabels(t, oldLabels, r.GetNodeLabels(netip.MustParseAddr(address), allocatedHint(localClusterID)))
	}
	require.Empty(t, r.GetNodeLabels(netip.MustParseAddr("10.244.0.1"), allocatedHint(localClusterID)),
		"pod allocation CIDRs are not node-owned direct addresses")

	replacement := nodeWithAddresses(localCluster, "node-a", localClusterID,
		map[string]string{"version": "two"}, "192.0.2.20")
	r.NodeUpsert(replacement)
	r.NodeUpsert(replacement) // duplicate accepted updates remain idempotent

	for _, stale := range []string{"192.0.2.10", "192.0.2.11", "2001:db8::11", "192.0.2.12", "2001:db8::12"} {
		require.Empty(t, r.GetNodeLabels(netip.MustParseAddr(stale), allocatedHint(localClusterID)))
	}
	requireLabels(t, []string{"version=two"},
		r.GetNodeLabels(netip.MustParseAddr("192.0.2.20"), allocatedHint(localClusterID)))
	requireLabels(t, []string{"a=first", "version=one"}, oldLabels,
		"published label snapshots must not be mutated by later updates")

	// An excluded upsert removes the complete previously accepted snapshot.
	replacement.ClusterID = remoteClusterID
	r.NodeUpsert(replacement)
	require.Empty(t, r.GetNodeLabels(netip.MustParseAddr("192.0.2.20"), allocatedHint(localClusterID)))

	// Delete is keyed by identity and ignores the event's missing addresses.
	replacement.ClusterID = localClusterID
	r.NodeUpsert(replacement)
	r.NodeDelete(nodeTypes.Node{Name: replacement.Name, Cluster: replacement.Cluster})
	require.Empty(t, r.GetNodeLabels(netip.MustParseAddr("192.0.2.20"), allocatedHint(localClusterID)))
}

func TestResolverSharedAddressDeletePreservesOtherOwner(t *testing.T) {
	ipc := newTestIPCache(t)
	r := NewResolver(ipc, cmtypes.ClusterInfo{ID: localClusterID, Name: localCluster}, nil)
	nodeA := nodeWithAddresses(localCluster, "node-a", localClusterID,
		map[string]string{"node": "a"}, "192.0.2.10")
	nodeB := nodeWithAddresses(localCluster, "node-b", localClusterID,
		map[string]string{"node": "b"}, "192.0.2.10")
	r.NodeUpsert(nodeA)
	r.NodeUpsert(nodeB)
	require.Empty(t, r.GetNodeLabels(netip.MustParseAddr("192.0.2.10"), allocatedHint(localClusterID)))

	r.NodeDelete(nodeTypes.Node{Name: nodeA.Name, Cluster: nodeA.Cluster})
	requireLabels(t, []string{"node=b"},
		r.GetNodeLabels(netip.MustParseAddr("192.0.2.10"), allocatedHint(localClusterID)))
}

func TestResolverConcurrentUpdatesAndLookups(t *testing.T) {
	ipc := newTestIPCache(t)
	r := NewResolver(ipc, cmtypes.ClusterInfo{ID: localClusterID, Name: localCluster}, nil)
	node := nodeWithAddresses(localCluster, "node-a", localClusterID,
		map[string]string{"node": "a"}, "192.0.2.10")
	r.NodeUpsert(node)
	upsertHost(t, ipc, "10.0.0.1", "192.0.2.10")

	const iterations = 500
	var wg sync.WaitGroup
	wg.Add(3)
	go func() {
		defer wg.Done()
		for range iterations {
			r.NodeUpsert(node)
		}
	}()
	go func() {
		defer wg.Done()
		for range iterations {
			r.NodeDelete(nodeTypes.Node{Name: node.Name, Cluster: node.Cluster})
			r.NodeUpsert(node)
		}
	}()
	go func() {
		defer wg.Done()
		for range iterations {
			labels := r.GetNodeLabels(netip.MustParseAddr("10.0.0.1"), allocatedHint(localClusterID))
			if len(labels) != 0 && (len(labels) != 1 || labels[0] != "node=a") {
				t.Errorf("lookup observed a partial snapshot: %v", labels)
			}
		}
	}()
	wg.Wait()
}
