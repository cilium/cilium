// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipcache

import (
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"

	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	identityPkg "github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/source"
	testidentity "github.com/cilium/cilium/pkg/testutils/identity"
	"github.com/cilium/cilium/pkg/types"
	"github.com/cilium/cilium/pkg/u8proto"
)

type IPCacheTestSuite struct {
	IPIdentityCache *IPCache
	PolicyHandler   *mockUpdater
	Allocator       *testidentity.MockIdentityAllocator
}

func setupIPCacheTestSuite(tb testing.TB) *IPCacheTestSuite {
	s := &IPCacheTestSuite{
		Allocator:     testidentity.NewMockIdentityAllocator(nil),
		PolicyHandler: newMockUpdater(),
	}
	s.IPIdentityCache = NewIPCache(&Configuration{
		Context:           tb.Context(),
		Logger:            hivetest.Logger(tb),
		IdentityAllocator: s.Allocator,
		IdentityUpdater:   s.PolicyHandler,
	})

	s.IPIdentityCache.metadata.upsertLocked(worldPrefix, source.KubeAPIServer, "kube-uid", labels.LabelKubeAPIServer)
	s.IPIdentityCache.metadata.upsertLocked(worldPrefix, source.Local, "host-uid", labels.LabelHost)

	tb.Cleanup(func() {
		s.IPIdentityCache.Shutdown()
	})

	return s
}

func TestIPCache(t *testing.T) {
	s := setupIPCacheTestSuite(t)
	t.Parallel()

	endpointIP := "10.0.0.15"
	identity := (identityPkg.NumericIdentity(68))

	// Assure sane state at start.
	require.Empty(t, s.IPIdentityCache.ipToIdentityCache)
	require.Empty(t, s.IPIdentityCache.identityToIPCache)

	// Deletion of key that doesn't exist doesn't cause panic.
	s.IPIdentityCache.Delete(endpointIP, source.KVStore)

	s.IPIdentityCache.Upsert(endpointIP, nil, 0, nil, Identity{
		ID:     identity,
		Source: source.KVStore,
	})

	// Assure both caches are updated..
	require.Len(t, s.IPIdentityCache.ipToIdentityCache, 1)
	require.Len(t, s.IPIdentityCache.identityToIPCache, 1)

	cachedIdentity, exists := s.IPIdentityCache.LookupByIP(endpointIP)
	require.True(t, exists)
	require.Equal(t, identity, cachedIdentity.ID)
	require.Equal(t, source.KVStore, cachedIdentity.Source)

	// kubernetes source cannot update kvstore source
	_, err := s.IPIdentityCache.Upsert(endpointIP, nil, 0, nil, Identity{
		ID:     identity,
		Source: source.Kubernetes,
	})
	require.ErrorIs(t, err, &ErrOverwrite{NewSrc: source.Kubernetes})

	s.IPIdentityCache.Upsert(endpointIP, nil, 0, nil, Identity{
		ID:     identity,
		Source: source.KVStore,
	})

	// No duplicates.
	require.Len(t, s.IPIdentityCache.ipToIdentityCache, 1)
	require.Len(t, s.IPIdentityCache.identityToIPCache, 1)

	s.IPIdentityCache.Delete(endpointIP, source.KVStore)

	// Assure deletion occurs across all mappings.
	require.Empty(t, s.IPIdentityCache.ipToIdentityCache)
	require.Empty(t, s.IPIdentityCache.identityToIPCache)
	require.Empty(t, s.IPIdentityCache.ipToHostIPCache)
	require.Empty(t, s.IPIdentityCache.ipToK8sMetadata)

	_, exists = s.IPIdentityCache.LookupByIP(endpointIP)

	require.False(t, exists)

	hostIP := net.ParseIP("192.168.1.10")
	k8sMeta := &K8sMetadata{
		Namespace: "default",
		PodName:   "podname",
	}

	s.IPIdentityCache.Upsert(endpointIP, hostIP, 0, k8sMeta, Identity{
		ID:     identity,
		Source: source.KVStore,
	})

	cachedHostIP, _ := s.IPIdentityCache.getHostIPCacheRLocked(endpointIP)
	require.Equal(t, hostIP, cachedHostIP)
	require.Equal(t, k8sMeta, s.IPIdentityCache.GetK8sMetadata(netip.MustParseAddr(endpointIP)))

	newIdentity := identityPkg.NumericIdentity(69)
	s.IPIdentityCache.Upsert(endpointIP, hostIP, 0, k8sMeta, Identity{
		ID:     newIdentity,
		Source: source.KVStore,
	})

	// Ensure that update of cache with new identity doesn't keep old identity-to-ip
	// mapping around.
	ips := s.IPIdentityCache.LookupByIdentity(identity)
	require.Nil(t, ips)

	cachedIPs := s.IPIdentityCache.LookupByIdentity(newIdentity)
	require.NotNil(t, cachedIPs)
	for _, cachedIP := range cachedIPs {
		require.Equal(t, endpointIP, cachedIP)
	}

	s.IPIdentityCache.Delete(endpointIP, source.KVStore)

	// Assure deletion occurs across both mappings.
	require.Empty(t, s.IPIdentityCache.ipToIdentityCache)
	require.Empty(t, s.IPIdentityCache.identityToIPCache)
	require.Empty(t, s.IPIdentityCache.ipToHostIPCache)
	require.Empty(t, s.IPIdentityCache.ipToK8sMetadata)

	// Test mapping of multiple IPs to same identity.
	endpointIPs := []string{"192.168.0.1", "20.3.75.3", "27.2.2.2", "127.0.0.1", "127.0.0.1", "10.1.1.250"}
	identities := []identityPkg.NumericIdentity{5, 67, 29, 29, 29, 42}

	for index := range endpointIPs {
		s.IPIdentityCache.Upsert(endpointIPs[index], nil, 0, nil, Identity{
			ID:     identities[index],
			Source: source.KVStore,
		})
		cachedIdentity, _ := s.IPIdentityCache.LookupByIP(endpointIPs[index])
		require.Equal(t, identities[index], cachedIdentity.ID)
	}

	expectedIPList := []string{"127.0.0.1", "27.2.2.2"}

	cachedEndpointIPs := s.IPIdentityCache.LookupByIdentity(29)
	slices.Sort(cachedEndpointIPs)
	require.Equal(t, expectedIPList, cachedEndpointIPs)

	s.IPIdentityCache.Delete("27.2.2.2", source.KVStore)

	expectedIPList = []string{"127.0.0.1"}

	cachedEndpointIPs = s.IPIdentityCache.LookupByIdentity(29)
	require.Equal(t, expectedIPList, cachedEndpointIPs)

	cachedIdentity, exists = s.IPIdentityCache.LookupByIP("127.0.0.1")
	require.True(t, exists)
	require.Equal(t, identityPkg.NumericIdentity(29), cachedIdentity.ID)

	cachedIdentity, exists = s.IPIdentityCache.LookupByPrefix("127.0.0.1/32")
	require.True(t, exists)
	require.Equal(t, identityPkg.NumericIdentity(29), cachedIdentity.ID)

	s.IPIdentityCache.Delete("127.0.0.1", source.KVStore)

	ips = s.IPIdentityCache.LookupByIdentity(29)
	require.Nil(t, ips)

	_, exists = s.IPIdentityCache.LookupByPrefix("127.0.0.1/32")
	require.False(t, exists)

	// Assert IPCache entry is overwritten when a different pod (different
	// k8sMeta) with the same IP as what's already inside the IPCache is
	// inserted.
	_, err = s.IPIdentityCache.Upsert("10.1.1.250", net.ParseIP("10.0.0.1"), 0, &K8sMetadata{
		Namespace: "ns-1",
		PodName:   "pod1",
	}, Identity{
		ID:     42,
		Source: source.KVStore,
	})
	require.NoError(t, err)
	_, exists = s.IPIdentityCache.LookupByPrefix("10.1.1.250/32")
	require.True(t, exists)
	// Insert different pod now.
	_, err = s.IPIdentityCache.Upsert("10.1.1.250", net.ParseIP("10.0.0.2"), 0, &K8sMetadata{
		Namespace: "ns-1",
		PodName:   "pod2",
	}, Identity{
		ID:     43,
		Source: source.KVStore,
	})
	require.NoError(t, err)
	cachedIdentity, _ = s.IPIdentityCache.LookupByPrefix("10.1.1.250/32")
	require.Equal(t, identityPkg.NumericIdentity(43), cachedIdentity.ID) // Assert entry overwritten.
	// Assuming different pod with same IP 10.1.1.250 as a previous pod was
	// deleted, assert IPCache entry is deleted is still deleted.
	s.IPIdentityCache.Delete("10.1.1.250", source.KVStore)
	_, exists = s.IPIdentityCache.LookupByPrefix("10.1.1.250/32")
	require.False(t, exists) // Assert entry deleted.

	// Clean up.
	for index := range endpointIPs {
		s.IPIdentityCache.Delete(endpointIPs[index], source.KVStore)
		_, exists = s.IPIdentityCache.LookupByIP(endpointIPs[index])
		require.False(t, exists)

		ips = s.IPIdentityCache.LookupByIdentity(identities[index])
		require.Nil(t, ips)
	}

	require.Empty(t, s.IPIdentityCache.ipToIdentityCache)
	require.Empty(t, s.IPIdentityCache.identityToIPCache)
}

func TestIPCacheNamedPorts(t *testing.T) {
	s := setupIPCacheTestSuite(t)
	t.Parallel()

	endpointIP := "10.0.0.15"
	identity := identityPkg.NumericIdentity(68)

	// Assure sane state at start.
	require.Empty(t, s.IPIdentityCache.ipToIdentityCache)
	require.Empty(t, s.IPIdentityCache.identityToIPCache)

	// Deletion of key that doesn't exist doesn't cause panic.
	namedPortsChanged := s.IPIdentityCache.Delete(endpointIP, source.KVStore)
	require.False(t, namedPortsChanged)

	meta := K8sMetadata{
		Namespace: "default",
		PodName:   "app1",
		NamedPorts: types.NamedPortMap{
			"http": types.PortProto{Port: 80, Proto: u8proto.TCP},
			"dns":  types.PortProto{Port: 53},
		},
	}

	namedPortsChanged, err := s.IPIdentityCache.Upsert(endpointIP, nil, 0, &meta, Identity{
		ID:     identity,
		Source: source.Kubernetes,
	})
	require.NoError(t, err)

	// Assure both caches are updated..
	require.Len(t, s.IPIdentityCache.ipToIdentityCache, 1)
	require.Len(t, s.IPIdentityCache.identityToIPCache, 1)
	require.Empty(t, s.IPIdentityCache.ipToHostIPCache)
	require.Len(t, s.IPIdentityCache.ipToK8sMetadata, 1)

	cachedIdentity, exists := s.IPIdentityCache.LookupByIP(endpointIP)
	require.True(t, exists)
	require.Equal(t, identity, cachedIdentity.ID)
	require.Equal(t, source.Kubernetes, cachedIdentity.Source)

	// Named ports have been updated, but no policy uses them, hence don't
	// trigger policy regen until GetNamedPorts has been called at least once.
	require.False(t, namedPortsChanged)
	npm := s.IPIdentityCache.GetNamedPorts()
	require.NotNil(t, npm)
	require.Equal(t, 2, npm.Len())
	port, err := npm.GetNamedPort("http", u8proto.TCP)
	require.NoError(t, err)
	require.Equal(t, uint16(80), port)
	port, err = npm.GetNamedPort("dns", u8proto.ANY)
	require.NoError(t, err)
	require.Equal(t, uint16(53), port)

	// No duplicates.
	require.Len(t, s.IPIdentityCache.ipToIdentityCache, 1)
	require.Len(t, s.IPIdentityCache.identityToIPCache, 1)
	require.Empty(t, s.IPIdentityCache.ipToHostIPCache)
	require.Len(t, s.IPIdentityCache.ipToK8sMetadata, 1)

	cachedIdentity, exists = s.IPIdentityCache.LookupByIP(endpointIP)
	require.True(t, exists)
	require.Equal(t, identity, cachedIdentity.ID)
	require.Equal(t, source.Kubernetes, cachedIdentity.Source)

	// 2nd identity
	endpointIP2 := "10.0.0.16"
	identity2 := (identityPkg.NumericIdentity(70))

	meta2 := K8sMetadata{
		Namespace: "testing",
		PodName:   "app2",
		NamedPorts: types.NamedPortMap{
			"https": types.PortProto{Port: 443, Proto: u8proto.TCP},
			"dns":   types.PortProto{Port: 53},
		},
	}

	namedPortsChanged, err = s.IPIdentityCache.Upsert(endpointIP2, nil, 0, &meta2, Identity{
		ID:     identity2,
		Source: source.Kubernetes,
	})
	require.NoError(t, err)

	// Assure both caches are updated..
	require.Len(t, s.IPIdentityCache.ipToIdentityCache, 2)
	require.Len(t, s.IPIdentityCache.identityToIPCache, 2)
	require.Empty(t, s.IPIdentityCache.ipToHostIPCache)
	require.Len(t, s.IPIdentityCache.ipToK8sMetadata, 2)

	cachedIdentity, exists = s.IPIdentityCache.LookupByIP(endpointIP2)
	require.True(t, exists)
	require.Equal(t, identity2, cachedIdentity.ID)
	require.Equal(t, source.Kubernetes, cachedIdentity.Source)

	// Named ports have been updated
	require.True(t, namedPortsChanged)
	npm = s.IPIdentityCache.GetNamedPorts()
	require.NotNil(t, npm)
	require.Equal(t, 3, npm.Len())
	port, err = npm.GetNamedPort("http", u8proto.TCP)
	require.NoError(t, err)
	require.Equal(t, uint16(80), port)
	port, err = npm.GetNamedPort("dns", u8proto.ANY)
	require.NoError(t, err)
	require.Equal(t, uint16(53), port)
	port, err = npm.GetNamedPort("https", u8proto.TCP)
	require.NoError(t, err)
	require.Equal(t, uint16(443), port)

	namedPortsChanged = s.IPIdentityCache.Delete(endpointIP, source.Kubernetes)
	require.True(t, namedPortsChanged)
	npm = s.IPIdentityCache.GetNamedPorts()
	require.NotNil(t, npm)
	require.Equal(t, 2, npm.Len())

	port, err = npm.GetNamedPort("dns", u8proto.ANY)
	require.NoError(t, err)
	require.Equal(t, uint16(53), port)
	port, err = npm.GetNamedPort("https", u8proto.TCP)
	require.NoError(t, err)
	require.Equal(t, uint16(443), port)

	// Assure deletion occurs across all mappings.
	require.Len(t, s.IPIdentityCache.ipToIdentityCache, 1)
	require.Len(t, s.IPIdentityCache.identityToIPCache, 1)
	require.Empty(t, s.IPIdentityCache.ipToHostIPCache)
	require.Len(t, s.IPIdentityCache.ipToK8sMetadata, 1)

	_, exists = s.IPIdentityCache.LookupByIP(endpointIP)

	require.False(t, exists)

	hostIP := net.ParseIP("192.168.1.10")
	k8sMeta := &K8sMetadata{
		Namespace: "default",
		PodName:   "podname",
	}

	namedPortsChanged, err = s.IPIdentityCache.Upsert(endpointIP, hostIP, 0, k8sMeta, Identity{
		ID:     identity,
		Source: source.KVStore,
	})
	require.NoError(t, err)
	require.False(t, namedPortsChanged)

	// Assure upsert occurs across all mappings.
	require.Len(t, s.IPIdentityCache.ipToIdentityCache, 2)
	require.Len(t, s.IPIdentityCache.identityToIPCache, 2)
	require.Len(t, s.IPIdentityCache.ipToHostIPCache, 1)
	require.Len(t, s.IPIdentityCache.ipToK8sMetadata, 2)

	cachedHostIP, _ := s.IPIdentityCache.getHostIPCacheRLocked(endpointIP)
	require.Equal(t, hostIP, cachedHostIP)
	require.Equal(t, k8sMeta, s.IPIdentityCache.GetK8sMetadata(netip.MustParseAddr(endpointIP)))

	newIdentity := identityPkg.NumericIdentity(69)
	namedPortsChanged, err = s.IPIdentityCache.Upsert(endpointIP, hostIP, 0, k8sMeta, Identity{
		ID:     newIdentity,
		Source: source.KVStore,
	})
	require.NoError(t, err)
	require.False(t, namedPortsChanged)

	// Assure upsert occurs across all mappings.
	require.Len(t, s.IPIdentityCache.ipToIdentityCache, 2)
	require.Len(t, s.IPIdentityCache.identityToIPCache, 2)
	require.Len(t, s.IPIdentityCache.ipToHostIPCache, 1)
	require.Len(t, s.IPIdentityCache.ipToK8sMetadata, 2)

	// Ensure that update of cache with new identity doesn't keep old identity-to-ip
	// mapping around.
	ips := s.IPIdentityCache.LookupByIdentity(identity)
	require.Nil(t, ips)

	cachedIPs := s.IPIdentityCache.LookupByIdentity(newIdentity)
	require.NotNil(t, cachedIPs)
	for _, cachedIP := range cachedIPs {
		require.Equal(t, endpointIP, cachedIP)
	}

	namedPortsChanged = s.IPIdentityCache.Delete(endpointIP, source.KVStore)
	// Deleted identity did not have any named ports, so no change
	require.False(t, namedPortsChanged)

	// Assure deletion occurs across both mappings.
	require.Len(t, s.IPIdentityCache.ipToIdentityCache, 1)
	require.Len(t, s.IPIdentityCache.identityToIPCache, 1)
	require.Empty(t, s.IPIdentityCache.ipToHostIPCache)
	require.Len(t, s.IPIdentityCache.ipToK8sMetadata, 1)

	// Test mapping of multiple IPs to same identity.
	endpointIPs := []string{"192.168.0.1", "20.3.75.3", "27.2.2.2", "127.0.0.1", "127.0.0.1"}
	identities := []identityPkg.NumericIdentity{5, 67, 29, 29, 29}
	k8sMeta.NamedPorts = types.NamedPortMap{
		"http2": types.PortProto{Port: 8080, Proto: u8proto.TCP},
	}

	for index := range endpointIPs {
		k8sMeta.PodName = fmt.Sprintf("pod-%d", int(identities[index]))
		namedPortsChanged, err = s.IPIdentityCache.Upsert(endpointIPs[index], nil, 0, k8sMeta, Identity{
			ID:     identities[index],
			Source: source.KVStore,
		})
		require.NoError(t, err)
		npm = s.IPIdentityCache.GetNamedPorts()
		require.NotNil(t, npm)
		port, err := npm.GetNamedPort("http2", u8proto.TCP)
		require.NoError(t, err)
		require.Equal(t, uint16(8080), port)
		// only the first changes named ports, as they are all the same
		require.Equal(t, index == 0, namedPortsChanged)
		cachedIdentity, _ := s.IPIdentityCache.LookupByIP(endpointIPs[index])
		require.Equal(t, identities[index], cachedIdentity.ID)
	}

	expectedIPList := []string{"127.0.0.1", "27.2.2.2"}

	cachedEndpointIPs := s.IPIdentityCache.LookupByIdentity(29)
	slices.Sort(cachedEndpointIPs)
	require.Equal(t, expectedIPList, cachedEndpointIPs)

	namedPortsChanged = s.IPIdentityCache.Delete("27.2.2.2", source.KVStore)
	require.False(t, namedPortsChanged)

	expectedIPList = []string{"127.0.0.1"}

	cachedEndpointIPs = s.IPIdentityCache.LookupByIdentity(29)
	require.Equal(t, expectedIPList, cachedEndpointIPs)

	cachedIdentity, exists = s.IPIdentityCache.LookupByIP("127.0.0.1")
	require.True(t, exists)
	require.Equal(t, identityPkg.NumericIdentity(29), cachedIdentity.ID)

	cachedIdentity, exists = s.IPIdentityCache.LookupByPrefix("127.0.0.1/32")
	require.True(t, exists)
	require.Equal(t, identityPkg.NumericIdentity(29), cachedIdentity.ID)

	s.IPIdentityCache.Delete("127.0.0.1", source.KVStore)

	ips = s.IPIdentityCache.LookupByIdentity(29)
	require.Nil(t, ips)

	_, exists = s.IPIdentityCache.LookupByPrefix("127.0.0.1/32")
	require.False(t, exists)

	// Clean up.
	for index := range endpointIPs {
		namedPortsChanged = s.IPIdentityCache.Delete(endpointIPs[index], source.KVStore)
		npm = s.IPIdentityCache.GetNamedPorts()
		require.NotNil(t, npm)
		t.Logf("Named ports after Delete %d: %v", index, npm)
		// 2nd delete removes named port mapping, as remaining IPs have an already deleted ID (29)
		require.Equal(t, index == 1, namedPortsChanged)

		_, exists = s.IPIdentityCache.LookupByIP(endpointIPs[index])
		require.False(t, exists)

		ips = s.IPIdentityCache.LookupByIdentity(identities[index])
		require.Nil(t, ips)
	}

	require.Len(t, s.IPIdentityCache.ipToIdentityCache, 1)
	require.Len(t, s.IPIdentityCache.identityToIPCache, 1)

	namedPortsChanged = s.IPIdentityCache.Delete(endpointIP2, source.Kubernetes)
	require.True(t, namedPortsChanged)
	npm = s.IPIdentityCache.GetNamedPorts()
	require.Equal(t, 0, npm.Len())
}

func BenchmarkIPCacheUpsert10(b *testing.B) {
	benchmarkIPCacheUpsert(b, 10)
}

func BenchmarkIPCacheUpsert100(b *testing.B) {
	benchmarkIPCacheUpsert(b, 100)
}

func BenchmarkIPCacheUpsert1000(b *testing.B) {
	benchmarkIPCacheUpsert(b, 1000)
}

func BenchmarkIPCacheUpsert10000(b *testing.B) {
	benchmarkIPCacheUpsert(b, 10000)
}

func benchmarkIPCacheUpsert(b *testing.B, num int) {
	logger := hivetest.Logger(b)
	meta := K8sMetadata{
		Namespace: "default",
		PodName:   "app",
		NamedPorts: types.NamedPortMap{
			"http": types.PortProto{Port: 80, Proto: u8proto.TCP},
			"dns":  types.PortProto{Port: 53},
		},
	}

	buf := make([]byte, 4)
	ips := make([]string, num)
	nms := make([]string, num)
	for i := range nms {
		binary.BigEndian.PutUint32(buf, uint32(i+2<<26))
		ip, _ := netip.AddrFromSlice(buf)
		ips[i] = ip.String()
		nms[i] = strconv.Itoa(i)
	}

	ipcs := make([]*IPCache, 0, b.N)
	for range b.N {
		ipcache := NewIPCache(&Configuration{
			Context: b.Context(),
			Logger:  logger,
			//IdentityAllocator: allocator,
			IdentityUpdater: &mockUpdater{},
		})
		ipcs = append(ipcs, ipcache)
	}

	i := 0
	for b.Loop() {
		ipc := ipcs[i]
		i++

		for j := range num {
			meta.PodName = nms[j]
			_, err := ipc.Upsert(ips[j], nil, 0, &meta, Identity{
				ID:     identityPkg.NumericIdentity(j),
				Source: source.Kubernetes,
			})
			if err != nil {
				b.Fatalf("failed to upsert: %v", err)
			}
		}
	}
}

type dummyListener struct {
	entries map[string]identityPkg.NumericIdentity
	ipc     *IPCache
}

func newDummyListener(ipc *IPCache) *dummyListener {
	return &dummyListener{
		ipc: ipc,
	}
}

func (dl *dummyListener) OnIPIdentityCacheChange(modType CacheModification,
	cidrCluster cmtypes.PrefixCluster, oldHostIP, newHostIP net.IP, oldID *Identity,
	newID Identity, encryptKey uint8, k8sMeta *K8sMetadata, endpointFlags uint8) {

	switch modType {
	case Upsert:
		dl.entries[cidrCluster.String()] = newID.ID
	default:
		// Ignore, for simplicity we just clear the cache every time
	}
}

func (dl *dummyListener) ExpectMapping(t *testing.T, targetIP string, targetIdentity identityPkg.NumericIdentity) {
	// Identity lookup directly shows the expected mapping
	identity, exists := dl.ipc.LookupByPrefix(targetIP)
	require.True(t, exists)
	require.Equal(t, targetIdentity, identity.ID)

	// Dump reliably supplies the IP once and only the pod identity.
	dl.entries = make(map[string]identityPkg.NumericIdentity)
	dl.ipc.dumpToListenerLocked(dl)
	require.Equal(t, map[string]identityPkg.NumericIdentity{
		targetIP: targetIdentity,
	}, dl.entries)
}

func TestIPCacheShadowing(t *testing.T) {
	t.Parallel()
	s := setupIPCacheTestSuite(t)

	endpointIP := "10.0.0.15"
	cidrOverlap := "10.0.0.15/32"
	epIdentity := identityPkg.NumericIdentity(68)
	cidrIdentity := identityPkg.NumericIdentity(202)
	ipc := s.IPIdentityCache

	// Assure sane state at start.
	require.Equal(t, map[string]Identity{}, ipc.ipToIdentityCache)
	require.Equal(t, map[identityPkg.NumericIdentity]map[string]struct{}{}, ipc.identityToIPCache)

	// Upsert overlapping identities for the IP. Pod identity takes precedence.
	ipc.Upsert(endpointIP, nil, 0, nil, Identity{
		ID:     epIdentity,
		Source: source.KVStore,
	})
	ipc.Upsert(cidrOverlap, nil, 0, nil, Identity{
		ID:     cidrIdentity,
		Source: source.Generated,
	})
	ipcache := newDummyListener(ipc)
	ipcache.ExpectMapping(t, cidrOverlap, epIdentity)

	// Deleting pod identity shows that cidr identity is now used.
	ipc.Delete(endpointIP, source.KVStore)
	ipcache.ExpectMapping(t, cidrOverlap, cidrIdentity)

	// Reinsert of pod IP should shadow the CIDR identity again.
	ipc.Upsert(endpointIP, nil, 0, nil, Identity{
		ID:     epIdentity,
		Source: source.KVStore,
	})
	ipcache.ExpectMapping(t, cidrOverlap, epIdentity)

	// Deletion of the shadowed identity should not change the output.
	ipc.Delete(cidrOverlap, source.Generated)
	ipcache.ExpectMapping(t, cidrOverlap, epIdentity)

	// Clean up
	ipc.Delete(endpointIP, source.KVStore)
	_, exists := ipc.LookupByPrefix(cidrOverlap)
	require.False(t, exists)
}
