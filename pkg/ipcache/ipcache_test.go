// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipcache

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"testing"

	"github.com/stretchr/testify/require"

	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	identityPkg "github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/source"
	testidentity "github.com/cilium/cilium/pkg/testutils/identity"
	"github.com/cilium/cilium/pkg/types"
	"github.com/cilium/cilium/pkg/u8proto"
)

type IPCacheTestSuite struct{}

var (
	IPIdentityCache *IPCache
	PolicyHandler   *mockUpdater
	Allocator       *testidentity.MockIdentityAllocator
)

func setupIPCacheTestSuite(tb testing.TB) *IPCacheTestSuite {
	s := &IPCacheTestSuite{}

	ctx, cancel := context.WithCancel(context.Background())
	Allocator = testidentity.NewMockIdentityAllocator(nil)
	PolicyHandler = &mockUpdater{
		identities: make(map[identityPkg.NumericIdentity]labels.LabelArray),
	}
	IPIdentityCache = NewIPCache(&Configuration{
		Context:           ctx,
		IdentityAllocator: Allocator,
		PolicyHandler:     PolicyHandler,
		DatapathHandler:   &mockTriggerer{},
	})

	tb.Cleanup(func() {
		cancel()
		IPIdentityCache.Shutdown()
	})

	return s
}

func TestIPCache(t *testing.T) {
	setupIPCacheTestSuite(t)

	endpointIP := "10.0.0.15"
	identity := (identityPkg.NumericIdentity(68))

	// Assure sane state at start.
	require.Equal(t, 0, len(IPIdentityCache.ipToIdentityCache))
	require.Equal(t, 0, len(IPIdentityCache.identityToIPCache))

	// Deletion of key that doesn't exist doesn't cause panic.
	IPIdentityCache.Delete(endpointIP, source.KVStore)

	IPIdentityCache.Upsert(endpointIP, nil, 0, nil, Identity{
		ID:     identity,
		Source: source.KVStore,
	})

	// Assure both caches are updated..
	require.Equal(t, 1, len(IPIdentityCache.ipToIdentityCache))
	require.Equal(t, 1, len(IPIdentityCache.identityToIPCache))

	cachedIdentity, exists := IPIdentityCache.LookupByIP(endpointIP)
	require.Equal(t, true, exists)
	require.Equal(t, identity, cachedIdentity.ID)
	require.Equal(t, source.KVStore, cachedIdentity.Source)

	// kubernetes source cannot update kvstore source
	_, err := IPIdentityCache.Upsert(endpointIP, nil, 0, nil, Identity{
		ID:     identity,
		Source: source.Kubernetes,
	})
	require.Equal(t, true, errors.Is(err, &ErrOverwrite{NewSrc: source.Kubernetes}))

	IPIdentityCache.Upsert(endpointIP, nil, 0, nil, Identity{
		ID:     identity,
		Source: source.KVStore,
	})

	// No duplicates.
	require.Equal(t, 1, len(IPIdentityCache.ipToIdentityCache))
	require.Equal(t, 1, len(IPIdentityCache.identityToIPCache))

	IPIdentityCache.Delete(endpointIP, source.KVStore)

	// Assure deletion occurs across all mappings.
	require.Equal(t, 0, len(IPIdentityCache.ipToIdentityCache))
	require.Equal(t, 0, len(IPIdentityCache.identityToIPCache))
	require.Equal(t, 0, len(IPIdentityCache.ipToHostIPCache))
	require.Equal(t, 0, len(IPIdentityCache.ipToK8sMetadata))

	_, exists = IPIdentityCache.LookupByIP(endpointIP)

	require.Equal(t, false, exists)

	hostIP := net.ParseIP("192.168.1.10")
	k8sMeta := &K8sMetadata{
		Namespace: "default",
		PodName:   "podname",
	}

	IPIdentityCache.Upsert(endpointIP, hostIP, 0, k8sMeta, Identity{
		ID:     identity,
		Source: source.KVStore,
	})

	cachedHostIP, _ := IPIdentityCache.getHostIPCache(endpointIP)
	require.EqualValues(t, hostIP, cachedHostIP)
	require.EqualValues(t, k8sMeta, IPIdentityCache.GetK8sMetadata(netip.MustParseAddr(endpointIP)))

	newIdentity := identityPkg.NumericIdentity(69)
	IPIdentityCache.Upsert(endpointIP, hostIP, 0, k8sMeta, Identity{
		ID:     newIdentity,
		Source: source.KVStore,
	})

	// Ensure that update of cache with new identity doesn't keep old identity-to-ip
	// mapping around.
	ips := IPIdentityCache.LookupByIdentity(identity)
	require.Nil(t, ips)

	cachedIPs := IPIdentityCache.LookupByIdentity(newIdentity)
	require.NotNil(t, cachedIPs)
	for _, cachedIP := range cachedIPs {
		require.Equal(t, endpointIP, cachedIP)
	}

	IPIdentityCache.Delete(endpointIP, source.KVStore)

	// Assure deletion occurs across both mappings.
	require.Equal(t, 0, len(IPIdentityCache.ipToIdentityCache))
	require.Equal(t, 0, len(IPIdentityCache.identityToIPCache))
	require.Equal(t, 0, len(IPIdentityCache.ipToHostIPCache))
	require.Equal(t, 0, len(IPIdentityCache.ipToK8sMetadata))

	// Test mapping of multiple IPs to same identity.
	endpointIPs := []string{"192.168.0.1", "20.3.75.3", "27.2.2.2", "127.0.0.1", "127.0.0.1", "10.1.1.250"}
	identities := []identityPkg.NumericIdentity{5, 67, 29, 29, 29, 42}

	for index := range endpointIPs {
		IPIdentityCache.Upsert(endpointIPs[index], nil, 0, nil, Identity{
			ID:     identities[index],
			Source: source.KVStore,
		})
		cachedIdentity, _ := IPIdentityCache.LookupByIP(endpointIPs[index])
		require.Equal(t, identities[index], cachedIdentity.ID)
	}

	expectedIPList := []string{"127.0.0.1", "27.2.2.2"}

	cachedEndpointIPs := IPIdentityCache.LookupByIdentity(29)
	sort.Strings(cachedEndpointIPs)
	require.EqualValues(t, expectedIPList, cachedEndpointIPs)

	IPIdentityCache.Delete("27.2.2.2", source.KVStore)

	expectedIPList = []string{"127.0.0.1"}

	cachedEndpointIPs = IPIdentityCache.LookupByIdentity(29)
	require.EqualValues(t, expectedIPList, cachedEndpointIPs)

	cachedIdentity, exists = IPIdentityCache.LookupByIP("127.0.0.1")
	require.Equal(t, true, exists)
	require.Equal(t, identityPkg.NumericIdentity(29), cachedIdentity.ID)

	cachedIdentity, exists = IPIdentityCache.LookupByPrefix("127.0.0.1/32")
	require.Equal(t, true, exists)
	require.Equal(t, identityPkg.NumericIdentity(29), cachedIdentity.ID)

	IPIdentityCache.Delete("127.0.0.1", source.KVStore)

	ips = IPIdentityCache.LookupByIdentity(29)
	require.Nil(t, ips)

	_, exists = IPIdentityCache.LookupByPrefix("127.0.0.1/32")
	require.Equal(t, false, exists)

	// Assert IPCache entry is overwritten when a different pod (different
	// k8sMeta) with the same IP as what's already inside the IPCache is
	// inserted.
	_, err = IPIdentityCache.Upsert("10.1.1.250", net.ParseIP("10.0.0.1"), 0, &K8sMetadata{
		Namespace: "ns-1",
		PodName:   "pod1",
	}, Identity{
		ID:     42,
		Source: source.KVStore,
	})
	require.Nil(t, err)
	_, exists = IPIdentityCache.LookupByPrefix("10.1.1.250/32")
	require.Equal(t, true, exists)
	// Insert different pod now.
	_, err = IPIdentityCache.Upsert("10.1.1.250", net.ParseIP("10.0.0.2"), 0, &K8sMetadata{
		Namespace: "ns-1",
		PodName:   "pod2",
	}, Identity{
		ID:     43,
		Source: source.KVStore,
	})
	require.Nil(t, err)
	cachedIdentity, _ = IPIdentityCache.LookupByPrefix("10.1.1.250/32")
	require.Equal(t, identityPkg.NumericIdentity(43), cachedIdentity.ID) // Assert entry overwritten.
	// Assuming different pod with same IP 10.1.1.250 as a previous pod was
	// deleted, assert IPCache entry is deleted is still deleted.
	IPIdentityCache.Delete("10.1.1.250", source.KVStore)
	_, exists = IPIdentityCache.LookupByPrefix("10.1.1.250/32")
	require.Equal(t, false, exists) // Assert entry deleted.

	// Clean up.
	for index := range endpointIPs {
		IPIdentityCache.Delete(endpointIPs[index], source.KVStore)
		_, exists = IPIdentityCache.LookupByIP(endpointIPs[index])
		require.Equal(t, false, exists)

		ips = IPIdentityCache.LookupByIdentity(identities[index])
		require.Nil(t, ips)
	}

	require.Equal(t, 0, len(IPIdentityCache.ipToIdentityCache))
	require.Equal(t, 0, len(IPIdentityCache.identityToIPCache))
}

func TestIPCacheNamedPorts(t *testing.T) {
	endpointIP := "10.0.0.15"
	identity := identityPkg.NumericIdentity(68)

	// Assure sane state at start.
	require.Equal(t, 0, len(IPIdentityCache.ipToIdentityCache))
	require.Equal(t, 0, len(IPIdentityCache.identityToIPCache))

	// Deletion of key that doesn't exist doesn't cause panic.
	namedPortsChanged := IPIdentityCache.Delete(endpointIP, source.KVStore)
	require.Equal(t, false, namedPortsChanged)

	meta := K8sMetadata{
		Namespace: "default",
		PodName:   "app1",
		NamedPorts: types.NamedPortMap{
			"http": types.PortProto{Port: 80, Proto: u8proto.TCP},
			"dns":  types.PortProto{Port: 53},
		},
	}

	namedPortsChanged, err := IPIdentityCache.Upsert(endpointIP, nil, 0, &meta, Identity{
		ID:     identity,
		Source: source.Kubernetes,
	})
	require.Nil(t, err)

	// Assure both caches are updated..
	require.Equal(t, 1, len(IPIdentityCache.ipToIdentityCache))
	require.Equal(t, 1, len(IPIdentityCache.identityToIPCache))
	require.Equal(t, 0, len(IPIdentityCache.ipToHostIPCache))
	require.Equal(t, 1, len(IPIdentityCache.ipToK8sMetadata))

	cachedIdentity, exists := IPIdentityCache.LookupByIP(endpointIP)
	require.Equal(t, true, exists)
	require.Equal(t, identity, cachedIdentity.ID)
	require.Equal(t, source.Kubernetes, cachedIdentity.Source)

	// Named ports have been updated, but no policy uses them, hence don't
	// trigger policy regen until GetNamedPorts has been called at least once.
	require.Equal(t, false, namedPortsChanged)
	npm := IPIdentityCache.GetNamedPorts()
	require.NotNil(t, npm)
	require.Equal(t, 2, npm.Len())
	port, err := npm.GetNamedPort("http", u8proto.TCP)
	require.Nil(t, err)
	require.Equal(t, uint16(80), port)
	port, err = npm.GetNamedPort("dns", u8proto.ANY)
	require.Nil(t, err)
	require.Equal(t, uint16(53), port)

	// No duplicates.
	require.Equal(t, 1, len(IPIdentityCache.ipToIdentityCache))
	require.Equal(t, 1, len(IPIdentityCache.identityToIPCache))
	require.Equal(t, 0, len(IPIdentityCache.ipToHostIPCache))
	require.Equal(t, 1, len(IPIdentityCache.ipToK8sMetadata))

	cachedIdentity, exists = IPIdentityCache.LookupByIP(endpointIP)
	require.Equal(t, true, exists)
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

	namedPortsChanged, err = IPIdentityCache.Upsert(endpointIP2, nil, 0, &meta2, Identity{
		ID:     identity2,
		Source: source.Kubernetes,
	})
	require.Nil(t, err)

	// Assure both caches are updated..
	require.Equal(t, 2, len(IPIdentityCache.ipToIdentityCache))
	require.Equal(t, 2, len(IPIdentityCache.identityToIPCache))
	require.Equal(t, 0, len(IPIdentityCache.ipToHostIPCache))
	require.Equal(t, 2, len(IPIdentityCache.ipToK8sMetadata))

	cachedIdentity, exists = IPIdentityCache.LookupByIP(endpointIP2)
	require.Equal(t, true, exists)
	require.Equal(t, identity2, cachedIdentity.ID)
	require.Equal(t, source.Kubernetes, cachedIdentity.Source)

	// Named ports have been updated
	require.Equal(t, true, namedPortsChanged)
	npm = IPIdentityCache.GetNamedPorts()
	require.NotNil(t, npm)
	require.Equal(t, 3, npm.Len())
	port, err = npm.GetNamedPort("http", u8proto.TCP)
	require.Nil(t, err)
	require.Equal(t, uint16(80), port)
	port, err = npm.GetNamedPort("dns", u8proto.ANY)
	require.Nil(t, err)
	require.Equal(t, uint16(53), port)
	port, err = npm.GetNamedPort("https", u8proto.TCP)
	require.Nil(t, err)
	require.Equal(t, uint16(443), port)

	namedPortsChanged = IPIdentityCache.Delete(endpointIP, source.Kubernetes)
	require.Equal(t, true, namedPortsChanged)
	npm = IPIdentityCache.GetNamedPorts()
	require.NotNil(t, npm)
	require.Equal(t, 2, npm.Len())

	port, err = npm.GetNamedPort("dns", u8proto.ANY)
	require.Nil(t, err)
	require.Equal(t, uint16(53), port)
	port, err = npm.GetNamedPort("https", u8proto.TCP)
	require.Nil(t, err)
	require.Equal(t, uint16(443), port)

	// Assure deletion occurs across all mappings.
	require.Equal(t, 1, len(IPIdentityCache.ipToIdentityCache))
	require.Equal(t, 1, len(IPIdentityCache.identityToIPCache))
	require.Equal(t, 0, len(IPIdentityCache.ipToHostIPCache))
	require.Equal(t, 1, len(IPIdentityCache.ipToK8sMetadata))

	_, exists = IPIdentityCache.LookupByIP(endpointIP)

	require.Equal(t, false, exists)

	hostIP := net.ParseIP("192.168.1.10")
	k8sMeta := &K8sMetadata{
		Namespace: "default",
		PodName:   "podname",
	}

	namedPortsChanged, err = IPIdentityCache.Upsert(endpointIP, hostIP, 0, k8sMeta, Identity{
		ID:     identity,
		Source: source.KVStore,
	})
	require.Nil(t, err)
	require.Equal(t, false, namedPortsChanged)

	// Assure upsert occurs across all mappings.
	require.Equal(t, 2, len(IPIdentityCache.ipToIdentityCache))
	require.Equal(t, 2, len(IPIdentityCache.identityToIPCache))
	require.Equal(t, 1, len(IPIdentityCache.ipToHostIPCache))
	require.Equal(t, 2, len(IPIdentityCache.ipToK8sMetadata))

	cachedHostIP, _ := IPIdentityCache.getHostIPCache(endpointIP)
	require.EqualValues(t, hostIP, cachedHostIP)
	require.EqualValues(t, k8sMeta, IPIdentityCache.GetK8sMetadata(netip.MustParseAddr(endpointIP)))

	newIdentity := identityPkg.NumericIdentity(69)
	namedPortsChanged, err = IPIdentityCache.Upsert(endpointIP, hostIP, 0, k8sMeta, Identity{
		ID:     newIdentity,
		Source: source.KVStore,
	})
	require.Nil(t, err)
	require.Equal(t, false, namedPortsChanged)

	// Assure upsert occurs across all mappings.
	require.Equal(t, 2, len(IPIdentityCache.ipToIdentityCache))
	require.Equal(t, 2, len(IPIdentityCache.identityToIPCache))
	require.Equal(t, 1, len(IPIdentityCache.ipToHostIPCache))
	require.Equal(t, 2, len(IPIdentityCache.ipToK8sMetadata))

	// Ensure that update of cache with new identity doesn't keep old identity-to-ip
	// mapping around.
	ips := IPIdentityCache.LookupByIdentity(identity)
	require.Nil(t, ips)

	cachedIPs := IPIdentityCache.LookupByIdentity(newIdentity)
	require.NotNil(t, cachedIPs)
	for _, cachedIP := range cachedIPs {
		require.Equal(t, endpointIP, cachedIP)
	}

	namedPortsChanged = IPIdentityCache.Delete(endpointIP, source.KVStore)
	// Deleted identity did not have any named ports, so no change
	require.Equal(t, false, namedPortsChanged)

	// Assure deletion occurs across both mappings.
	require.Equal(t, 1, len(IPIdentityCache.ipToIdentityCache))
	require.Equal(t, 1, len(IPIdentityCache.identityToIPCache))
	require.Equal(t, 0, len(IPIdentityCache.ipToHostIPCache))
	require.Equal(t, 1, len(IPIdentityCache.ipToK8sMetadata))

	// Test mapping of multiple IPs to same identity.
	endpointIPs := []string{"192.168.0.1", "20.3.75.3", "27.2.2.2", "127.0.0.1", "127.0.0.1"}
	identities := []identityPkg.NumericIdentity{5, 67, 29, 29, 29}
	k8sMeta.NamedPorts = types.NamedPortMap{
		"http2": types.PortProto{Port: 8080, Proto: u8proto.TCP},
	}

	for index := range endpointIPs {
		k8sMeta.PodName = fmt.Sprintf("pod-%d", int(identities[index]))
		namedPortsChanged, err = IPIdentityCache.Upsert(endpointIPs[index], nil, 0, k8sMeta, Identity{
			ID:     identities[index],
			Source: source.KVStore,
		})
		require.Nil(t, err)
		npm = IPIdentityCache.GetNamedPorts()
		require.NotNil(t, npm)
		port, err := npm.GetNamedPort("http2", u8proto.TCP)
		require.Nil(t, err)
		require.Equal(t, uint16(8080), port)
		// only the first changes named ports, as they are all the same
		require.Equal(t, index == 0, namedPortsChanged)
		cachedIdentity, _ := IPIdentityCache.LookupByIP(endpointIPs[index])
		require.Equal(t, identities[index], cachedIdentity.ID)
	}

	expectedIPList := []string{"127.0.0.1", "27.2.2.2"}

	cachedEndpointIPs := IPIdentityCache.LookupByIdentity(29)
	sort.Strings(cachedEndpointIPs)
	require.EqualValues(t, expectedIPList, cachedEndpointIPs)

	namedPortsChanged = IPIdentityCache.Delete("27.2.2.2", source.KVStore)
	require.Equal(t, false, namedPortsChanged)

	expectedIPList = []string{"127.0.0.1"}

	cachedEndpointIPs = IPIdentityCache.LookupByIdentity(29)
	require.EqualValues(t, expectedIPList, cachedEndpointIPs)

	cachedIdentity, exists = IPIdentityCache.LookupByIP("127.0.0.1")
	require.Equal(t, true, exists)
	require.Equal(t, identityPkg.NumericIdentity(29), cachedIdentity.ID)

	cachedIdentity, exists = IPIdentityCache.LookupByPrefix("127.0.0.1/32")
	require.Equal(t, true, exists)
	require.Equal(t, identityPkg.NumericIdentity(29), cachedIdentity.ID)

	IPIdentityCache.Delete("127.0.0.1", source.KVStore)

	ips = IPIdentityCache.LookupByIdentity(29)
	require.Nil(t, ips)

	_, exists = IPIdentityCache.LookupByPrefix("127.0.0.1/32")
	require.Equal(t, false, exists)

	// Clean up.
	for index := range endpointIPs {
		namedPortsChanged = IPIdentityCache.Delete(endpointIPs[index], source.KVStore)
		npm = IPIdentityCache.GetNamedPorts()
		require.NotNil(t, npm)
		log.Infof("Named ports after Delete %d: %v", index, npm)
		// 2nd delete removes named port mapping, as remaining IPs have an already deleted ID (29)
		require.Equal(t, index == 1, namedPortsChanged)

		_, exists = IPIdentityCache.LookupByIP(endpointIPs[index])
		require.Equal(t, false, exists)

		ips = IPIdentityCache.LookupByIdentity(identities[index])
		require.Nil(t, ips)
	}

	require.Equal(t, 1, len(IPIdentityCache.ipToIdentityCache))
	require.Equal(t, 1, len(IPIdentityCache.identityToIPCache))

	namedPortsChanged = IPIdentityCache.Delete(endpointIP2, source.Kubernetes)
	require.Equal(t, true, namedPortsChanged)
	npm = IPIdentityCache.GetNamedPorts()
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

	b.StopTimer()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ctx, cancel := context.WithCancel(context.Background())
		allocator := testidentity.NewMockIdentityAllocator(nil)
		ipcache := NewIPCache(&Configuration{
			Context:           ctx,
			IdentityAllocator: allocator,
			PolicyHandler:     &mockUpdater{},
			DatapathHandler:   &mockTriggerer{},
		})

		// We only want to measure the calls to upsert.
		b.StartTimer()
		for j := 0; j < num; j++ {
			meta.PodName = nms[j]
			_, err := ipcache.Upsert(ips[j], nil, 0, &meta, Identity{
				ID:     identityPkg.NumericIdentity(j),
				Source: source.Kubernetes,
			})
			if err != nil {
				b.Fatalf("failed to upsert: %v", err)
			}
		}
		b.StopTimer()

		// Clean up after ourselves, so that the individual runs are comparable.
		cancel()
		ipcache.Shutdown()
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
	newID Identity, encryptKey uint8, k8sMeta *K8sMetadata) {

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
	require.Equal(t, true, exists)
	require.Equal(t, targetIdentity, identity.ID)

	// Dump reliably supplies the IP once and only the pod identity.
	dl.entries = make(map[string]identityPkg.NumericIdentity)
	dl.ipc.DumpToListenerLocked(dl)
	require.EqualValues(t, map[string]identityPkg.NumericIdentity{
		targetIP: targetIdentity,
	}, dl.entries)
}

func TestIPCacheShadowing(t *testing.T) {
	setupIPCacheTestSuite(t)

	endpointIP := "10.0.0.15"
	cidrOverlap := "10.0.0.15/32"
	epIdentity := identityPkg.NumericIdentity(68)
	cidrIdentity := identityPkg.NumericIdentity(202)
	ipc := IPIdentityCache

	// Assure sane state at start.
	require.EqualValues(t, map[string]Identity{}, ipc.ipToIdentityCache)
	require.EqualValues(t, map[identityPkg.NumericIdentity]map[string]struct{}{}, ipc.identityToIPCache)

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
	require.Equal(t, false, exists)
}
