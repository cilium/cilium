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

	. "github.com/cilium/checkmate"

	"github.com/cilium/cilium/pkg/checker"
	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	identityPkg "github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/source"
	testidentity "github.com/cilium/cilium/pkg/testutils/identity"
	"github.com/cilium/cilium/pkg/types"
	"github.com/cilium/cilium/pkg/u8proto"
)

// Hook up gocheck into the "go test" runner.
type IPCacheTestSuite struct {
	cleanup func()
}

var (
	_               = Suite(&IPCacheTestSuite{})
	IPIdentityCache *IPCache
)

func Test(t *testing.T) {
	TestingT(t)
}

func (s *IPCacheTestSuite) SetUpTest(c *C) {
	ctx, cancel := context.WithCancel(context.Background())
	allocator := testidentity.NewMockIdentityAllocator(nil)
	IPIdentityCache = NewIPCache(&Configuration{
		Context:           ctx,
		IdentityAllocator: allocator,
		PolicyHandler:     &mockUpdater{},
		DatapathHandler:   &mockTriggerer{},
		NodeIDHandler:     &mockNodeIDHandler{},
	})

	s.cleanup = func() {
		cancel()
		IPIdentityCache.Shutdown()
	}
}

func (s *IPCacheTestSuite) TearDownTest(c *C) {
	s.cleanup()
}

func (s *IPCacheTestSuite) TestIPCache(c *C) {
	endpointIP := "10.0.0.15"
	identity := (identityPkg.NumericIdentity(68))

	// Assure sane state at start.
	c.Assert(len(IPIdentityCache.ipToIdentityCache), Equals, 0)
	c.Assert(len(IPIdentityCache.identityToIPCache), Equals, 0)

	// Deletion of key that doesn't exist doesn't cause panic.
	IPIdentityCache.Delete(endpointIP, source.KVStore)

	IPIdentityCache.Upsert(endpointIP, nil, 0, nil, Identity{
		ID:     identity,
		Source: source.KVStore,
	})

	// Assure both caches are updated..
	c.Assert(len(IPIdentityCache.ipToIdentityCache), Equals, 1)
	c.Assert(len(IPIdentityCache.identityToIPCache), Equals, 1)

	cachedIdentity, exists := IPIdentityCache.LookupByIP(endpointIP)
	c.Assert(exists, Equals, true)
	c.Assert(cachedIdentity.ID, Equals, identity)
	c.Assert(cachedIdentity.Source, Equals, source.KVStore)

	// kubernetes source cannot update kvstore source
	_, err := IPIdentityCache.Upsert(endpointIP, nil, 0, nil, Identity{
		ID:     identity,
		Source: source.Kubernetes,
	})
	c.Assert(errors.Is(err, &ErrOverwrite{NewSrc: source.Kubernetes}), Equals, true)

	IPIdentityCache.Upsert(endpointIP, nil, 0, nil, Identity{
		ID:     identity,
		Source: source.KVStore,
	})

	// No duplicates.
	c.Assert(len(IPIdentityCache.ipToIdentityCache), Equals, 1)
	c.Assert(len(IPIdentityCache.identityToIPCache), Equals, 1)

	IPIdentityCache.Delete(endpointIP, source.KVStore)

	// Assure deletion occurs across all mappings.
	c.Assert(len(IPIdentityCache.ipToIdentityCache), Equals, 0)
	c.Assert(len(IPIdentityCache.identityToIPCache), Equals, 0)
	c.Assert(len(IPIdentityCache.ipToHostIPCache), Equals, 0)
	c.Assert(len(IPIdentityCache.ipToK8sMetadata), Equals, 0)

	_, exists = IPIdentityCache.LookupByIP(endpointIP)

	c.Assert(exists, Equals, false)

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
	c.Assert(cachedHostIP, checker.DeepEquals, hostIP)
	c.Assert(IPIdentityCache.GetK8sMetadata(endpointIP), checker.DeepEquals, k8sMeta)

	newIdentity := identityPkg.NumericIdentity(69)
	IPIdentityCache.Upsert(endpointIP, hostIP, 0, k8sMeta, Identity{
		ID:     newIdentity,
		Source: source.KVStore,
	})

	// Ensure that update of cache with new identity doesn't keep old identity-to-ip
	// mapping around.
	ips := IPIdentityCache.LookupByIdentity(identity)
	c.Assert(ips, IsNil)

	cachedIPs := IPIdentityCache.LookupByIdentity(newIdentity)
	c.Assert(cachedIPs, Not(IsNil))
	for _, cachedIP := range cachedIPs {
		c.Assert(cachedIP, Equals, endpointIP)
	}

	IPIdentityCache.Delete(endpointIP, source.KVStore)

	// Assure deletion occurs across both mappings.
	c.Assert(len(IPIdentityCache.ipToIdentityCache), Equals, 0)
	c.Assert(len(IPIdentityCache.identityToIPCache), Equals, 0)
	c.Assert(len(IPIdentityCache.ipToHostIPCache), Equals, 0)
	c.Assert(len(IPIdentityCache.ipToK8sMetadata), Equals, 0)

	// Test mapping of multiple IPs to same identity.
	endpointIPs := []string{"192.168.0.1", "20.3.75.3", "27.2.2.2", "127.0.0.1", "127.0.0.1", "10.1.1.250"}
	identities := []identityPkg.NumericIdentity{5, 67, 29, 29, 29, 42}

	for index := range endpointIPs {
		IPIdentityCache.Upsert(endpointIPs[index], nil, 0, nil, Identity{
			ID:     identities[index],
			Source: source.KVStore,
		})
		cachedIdentity, _ := IPIdentityCache.LookupByIP(endpointIPs[index])
		c.Assert(cachedIdentity.ID, Equals, identities[index])
	}

	expectedIPList := []string{"127.0.0.1", "27.2.2.2"}

	cachedEndpointIPs := IPIdentityCache.LookupByIdentity(29)
	sort.Strings(cachedEndpointIPs)
	c.Assert(cachedEndpointIPs, checker.DeepEquals, expectedIPList)

	IPIdentityCache.Delete("27.2.2.2", source.KVStore)

	expectedIPList = []string{"127.0.0.1"}

	cachedEndpointIPs = IPIdentityCache.LookupByIdentity(29)
	c.Assert(cachedEndpointIPs, checker.DeepEquals, expectedIPList)

	cachedIdentity, exists = IPIdentityCache.LookupByIP("127.0.0.1")
	c.Assert(exists, Equals, true)
	c.Assert(cachedIdentity.ID, Equals, identityPkg.NumericIdentity(29))

	cachedIdentity, exists = IPIdentityCache.LookupByPrefix("127.0.0.1/32")
	c.Assert(exists, Equals, true)
	c.Assert(cachedIdentity.ID, Equals, identityPkg.NumericIdentity(29))

	IPIdentityCache.Delete("127.0.0.1", source.KVStore)

	ips = IPIdentityCache.LookupByIdentity(29)
	c.Assert(ips, IsNil)

	_, exists = IPIdentityCache.LookupByPrefix("127.0.0.1/32")
	c.Assert(exists, Equals, false)

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
	c.Assert(err, IsNil)
	_, exists = IPIdentityCache.LookupByPrefix("10.1.1.250/32")
	c.Assert(exists, Equals, true)
	// Insert different pod now.
	_, err = IPIdentityCache.Upsert("10.1.1.250", net.ParseIP("10.0.0.2"), 0, &K8sMetadata{
		Namespace: "ns-1",
		PodName:   "pod2",
	}, Identity{
		ID:     43,
		Source: source.KVStore,
	})
	c.Assert(err, IsNil)
	cachedIdentity, _ = IPIdentityCache.LookupByPrefix("10.1.1.250/32")
	c.Assert(cachedIdentity.ID, Equals, identityPkg.NumericIdentity(43)) // Assert entry overwritten.
	// Assuming different pod with same IP 10.1.1.250 as a previous pod was
	// deleted, assert IPCache entry is deleted is still deleted.
	IPIdentityCache.Delete("10.1.1.250", source.KVStore)
	_, exists = IPIdentityCache.LookupByPrefix("10.1.1.250/32")
	c.Assert(exists, Equals, false) // Assert entry deleted.

	// Clean up.
	for index := range endpointIPs {
		IPIdentityCache.Delete(endpointIPs[index], source.KVStore)
		_, exists = IPIdentityCache.LookupByIP(endpointIPs[index])
		c.Assert(exists, Equals, false)

		ips = IPIdentityCache.LookupByIdentity(identities[index])
		c.Assert(ips, IsNil)
	}

	c.Assert(len(IPIdentityCache.ipToIdentityCache), Equals, 0)
	c.Assert(len(IPIdentityCache.identityToIPCache), Equals, 0)
}

func (s *IPCacheTestSuite) TestKeyToIPNet(c *C) {
	// Valid IPv6.
	validIPv6Key := "cilium/state/ip/v1/default/f00d::a00:0:0:c164"

	_, expectedIPv6, err := net.ParseCIDR("f00d::a00:0:0:c164/128")
	c.Assert(err, IsNil)

	ipv6, isHost, err := keyToIPNet(validIPv6Key)
	c.Assert(ipv6, Not(IsNil))
	c.Assert(err, IsNil)
	c.Assert(isHost, Equals, true)
	c.Assert(ipv6, checker.DeepEquals, expectedIPv6)

	// Valid IPv6 prefix.
	validIPv6Key = "cilium/state/ip/v1/default/f00d::a00:0:0:0/64"

	_, expectedIPv6, err = net.ParseCIDR("f00d::a00:0:0:0/64")
	c.Assert(err, IsNil)

	ipv6, isHost, err = keyToIPNet(validIPv6Key)
	c.Assert(ipv6, Not(IsNil))
	c.Assert(err, IsNil)
	c.Assert(isHost, Equals, false)
	c.Assert(ipv6, checker.DeepEquals, expectedIPv6)

	// Valid IPv4.
	validIPv4Key := "cilium/state/ip/v1/default/10.0.114.197"
	_, expectedIPv4, err := net.ParseCIDR("10.0.114.197/32")
	c.Assert(err, IsNil)
	ipv4, isHost, err := keyToIPNet(validIPv4Key)
	c.Assert(ipv4, Not(IsNil))
	c.Assert(err, IsNil)
	c.Assert(isHost, Equals, true)
	c.Assert(ipv4, checker.DeepEquals, expectedIPv4)

	// Valid IPv4 prefix.
	validIPv4Key = "cilium/state/ip/v1/default/10.0.114.0/24"
	_, expectedIPv4, err = net.ParseCIDR("10.0.114.0/24")
	c.Assert(err, IsNil)
	ipv4, isHost, err = keyToIPNet(validIPv4Key)
	c.Assert(ipv4, Not(IsNil))
	c.Assert(err, IsNil)
	c.Assert(isHost, Equals, false)
	c.Assert(ipv4, checker.DeepEquals, expectedIPv4)

	// Invalid prefix.
	invalidPrefixKey := "cilium/state/foobar/v1/default/f00d::a00:0:0:c164"
	nilIP, isHost, err := keyToIPNet(invalidPrefixKey)
	c.Assert(nilIP, IsNil)
	c.Assert(err, Not(IsNil))
	c.Assert(isHost, Equals, false)

	// Invalid IP in key.
	invalidIPKey := "cilium/state/ip/v1/default/10.abfd.114.197"
	nilIP, isHost, err = keyToIPNet(invalidIPKey)
	c.Assert(nilIP, IsNil)
	c.Assert(err, Not(IsNil))
	c.Assert(isHost, Equals, false)

	// Invalid CIDR.
	invalidIPKey = "cilium/state/ip/v1/default/192.0.2.3/54"
	nilIP, isHost, err = keyToIPNet(invalidIPKey)
	c.Assert(nilIP, IsNil)
	c.Assert(err, Not(IsNil))
	c.Assert(isHost, Equals, false)
}

func (s *IPCacheTestSuite) TestIPCacheNamedPorts(c *C) {
	endpointIP := "10.0.0.15"
	identity := (identityPkg.NumericIdentity(68))

	// Assure sane state at start.
	c.Assert(len(IPIdentityCache.ipToIdentityCache), Equals, 0)
	c.Assert(len(IPIdentityCache.identityToIPCache), Equals, 0)

	// Deletion of key that doesn't exist doesn't cause panic.
	namedPortsChanged := IPIdentityCache.Delete(endpointIP, source.KVStore)
	c.Assert(namedPortsChanged, Equals, false)

	meta := K8sMetadata{
		Namespace: "default",
		PodName:   "app1",
		NamedPorts: types.NamedPortMap{
			"http": types.PortProto{Port: 80, Proto: uint8(u8proto.TCP)},
			"dns":  types.PortProto{Port: 53},
		},
	}

	namedPortsChanged, err := IPIdentityCache.Upsert(endpointIP, nil, 0, &meta, Identity{
		ID:     identity,
		Source: source.Kubernetes,
	})
	c.Assert(err, IsNil)

	// Assure both caches are updated..
	c.Assert(len(IPIdentityCache.ipToIdentityCache), Equals, 1)
	c.Assert(len(IPIdentityCache.identityToIPCache), Equals, 1)
	c.Assert(len(IPIdentityCache.ipToHostIPCache), Equals, 0)
	c.Assert(len(IPIdentityCache.ipToK8sMetadata), Equals, 1)

	cachedIdentity, exists := IPIdentityCache.LookupByIP(endpointIP)
	c.Assert(exists, Equals, true)
	c.Assert(cachedIdentity.ID, Equals, identity)
	c.Assert(cachedIdentity.Source, Equals, source.Kubernetes)

	// Named ports have been updated, but no policy uses them, hence don't
	// trigger policy regen until GetNamedPorts has been called at least once.
	c.Assert(namedPortsChanged, Equals, false)
	npm := IPIdentityCache.GetNamedPorts()
	c.Assert(npm, NotNil)
	c.Assert(npm.Len(), Equals, 2)
	port, err := npm.GetNamedPort("http", uint8(6))
	c.Assert(err, IsNil)
	c.Assert(port, Equals, uint16(80))
	port, err = npm.GetNamedPort("dns", uint8(0))
	c.Assert(err, IsNil)
	c.Assert(port, Equals, uint16(53))

	// No duplicates.
	c.Assert(len(IPIdentityCache.ipToIdentityCache), Equals, 1)
	c.Assert(len(IPIdentityCache.identityToIPCache), Equals, 1)
	c.Assert(len(IPIdentityCache.ipToHostIPCache), Equals, 0)
	c.Assert(len(IPIdentityCache.ipToK8sMetadata), Equals, 1)

	cachedIdentity, exists = IPIdentityCache.LookupByIP(endpointIP)
	c.Assert(exists, Equals, true)
	c.Assert(cachedIdentity.ID, Equals, identity)
	c.Assert(cachedIdentity.Source, Equals, source.Kubernetes)

	// 2nd identity
	endpointIP2 := "10.0.0.16"
	identity2 := (identityPkg.NumericIdentity(70))

	meta2 := K8sMetadata{
		Namespace: "testing",
		PodName:   "app2",
		NamedPorts: types.NamedPortMap{
			"https": types.PortProto{Port: 443, Proto: uint8(u8proto.TCP)},
			"dns":   types.PortProto{Port: 53},
		},
	}

	namedPortsChanged, err = IPIdentityCache.Upsert(endpointIP2, nil, 0, &meta2, Identity{
		ID:     identity2,
		Source: source.Kubernetes,
	})
	c.Assert(err, IsNil)

	// Assure both caches are updated..
	c.Assert(len(IPIdentityCache.ipToIdentityCache), Equals, 2)
	c.Assert(len(IPIdentityCache.identityToIPCache), Equals, 2)
	c.Assert(len(IPIdentityCache.ipToHostIPCache), Equals, 0)
	c.Assert(len(IPIdentityCache.ipToK8sMetadata), Equals, 2)

	cachedIdentity, exists = IPIdentityCache.LookupByIP(endpointIP2)
	c.Assert(exists, Equals, true)
	c.Assert(cachedIdentity.ID, Equals, identity2)
	c.Assert(cachedIdentity.Source, Equals, source.Kubernetes)

	// Named ports have been updated
	c.Assert(namedPortsChanged, Equals, true)
	npm = IPIdentityCache.GetNamedPorts()
	c.Assert(npm, NotNil)
	c.Assert(npm.Len(), Equals, 3)
	port, err = npm.GetNamedPort("http", uint8(6))
	c.Assert(err, IsNil)
	c.Assert(port, Equals, uint16(80))
	port, err = npm.GetNamedPort("dns", uint8(0))
	c.Assert(err, IsNil)
	c.Assert(port, Equals, uint16(53))
	port, err = npm.GetNamedPort("https", uint8(6))
	c.Assert(err, IsNil)
	c.Assert(port, Equals, uint16(443))

	namedPortsChanged = IPIdentityCache.Delete(endpointIP, source.Kubernetes)
	c.Assert(namedPortsChanged, Equals, true)
	npm = IPIdentityCache.GetNamedPorts()
	c.Assert(npm, NotNil)
	c.Assert(npm.Len(), Equals, 2)

	port, err = npm.GetNamedPort("dns", uint8(0))
	c.Assert(err, IsNil)
	c.Assert(port, Equals, uint16(53))
	port, err = npm.GetNamedPort("https", uint8(6))
	c.Assert(err, IsNil)
	c.Assert(port, Equals, uint16(443))

	// Assure deletion occurs across all mappings.
	c.Assert(len(IPIdentityCache.ipToIdentityCache), Equals, 1)
	c.Assert(len(IPIdentityCache.identityToIPCache), Equals, 1)
	c.Assert(len(IPIdentityCache.ipToHostIPCache), Equals, 0)
	c.Assert(len(IPIdentityCache.ipToK8sMetadata), Equals, 1)

	_, exists = IPIdentityCache.LookupByIP(endpointIP)

	c.Assert(exists, Equals, false)

	hostIP := net.ParseIP("192.168.1.10")
	k8sMeta := &K8sMetadata{
		Namespace: "default",
		PodName:   "podname",
	}

	namedPortsChanged, err = IPIdentityCache.Upsert(endpointIP, hostIP, 0, k8sMeta, Identity{
		ID:     identity,
		Source: source.KVStore,
	})
	c.Assert(err, IsNil)
	c.Assert(namedPortsChanged, Equals, false)

	// Assure upsert occurs across all mappings.
	c.Assert(len(IPIdentityCache.ipToIdentityCache), Equals, 2)
	c.Assert(len(IPIdentityCache.identityToIPCache), Equals, 2)
	c.Assert(len(IPIdentityCache.ipToHostIPCache), Equals, 1)
	c.Assert(len(IPIdentityCache.ipToK8sMetadata), Equals, 2)

	cachedHostIP, _ := IPIdentityCache.getHostIPCache(endpointIP)
	c.Assert(cachedHostIP, checker.DeepEquals, hostIP)
	c.Assert(IPIdentityCache.GetK8sMetadata(endpointIP), checker.DeepEquals, k8sMeta)

	newIdentity := identityPkg.NumericIdentity(69)
	namedPortsChanged, err = IPIdentityCache.Upsert(endpointIP, hostIP, 0, k8sMeta, Identity{
		ID:     newIdentity,
		Source: source.KVStore,
	})
	c.Assert(err, IsNil)
	c.Assert(namedPortsChanged, Equals, false)

	// Assure upsert occurs across all mappings.
	c.Assert(len(IPIdentityCache.ipToIdentityCache), Equals, 2)
	c.Assert(len(IPIdentityCache.identityToIPCache), Equals, 2)
	c.Assert(len(IPIdentityCache.ipToHostIPCache), Equals, 1)
	c.Assert(len(IPIdentityCache.ipToK8sMetadata), Equals, 2)

	// Ensure that update of cache with new identity doesn't keep old identity-to-ip
	// mapping around.
	ips := IPIdentityCache.LookupByIdentity(identity)
	c.Assert(ips, IsNil)

	cachedIPs := IPIdentityCache.LookupByIdentity(newIdentity)
	c.Assert(cachedIPs, Not(IsNil))
	for _, cachedIP := range cachedIPs {
		c.Assert(cachedIP, Equals, endpointIP)
	}

	namedPortsChanged = IPIdentityCache.Delete(endpointIP, source.KVStore)
	// Deleted identity did not have any named ports, so no change
	c.Assert(namedPortsChanged, Equals, false)

	// Assure deletion occurs across both mappings.
	c.Assert(len(IPIdentityCache.ipToIdentityCache), Equals, 1)
	c.Assert(len(IPIdentityCache.identityToIPCache), Equals, 1)
	c.Assert(len(IPIdentityCache.ipToHostIPCache), Equals, 0)
	c.Assert(len(IPIdentityCache.ipToK8sMetadata), Equals, 1)

	// Test mapping of multiple IPs to same identity.
	endpointIPs := []string{"192.168.0.1", "20.3.75.3", "27.2.2.2", "127.0.0.1", "127.0.0.1"}
	identities := []identityPkg.NumericIdentity{5, 67, 29, 29, 29}
	k8sMeta.NamedPorts = types.NamedPortMap{
		"http2": types.PortProto{Port: 8080, Proto: uint8(u8proto.TCP)},
	}

	for index := range endpointIPs {
		k8sMeta.PodName = fmt.Sprintf("pod-%d", int(identities[index]))
		namedPortsChanged, err = IPIdentityCache.Upsert(endpointIPs[index], nil, 0, k8sMeta, Identity{
			ID:     identities[index],
			Source: source.KVStore,
		})
		c.Assert(err, IsNil)
		npm = IPIdentityCache.GetNamedPorts()
		c.Assert(npm, NotNil)
		port, err := npm.GetNamedPort("http2", uint8(6))
		c.Assert(err, IsNil)
		c.Assert(port, Equals, uint16(8080))
		// only the first changes named ports, as they are all the same
		c.Assert(namedPortsChanged, Equals, index == 0)
		cachedIdentity, _ := IPIdentityCache.LookupByIP(endpointIPs[index])
		c.Assert(cachedIdentity.ID, Equals, identities[index])
	}

	expectedIPList := []string{"127.0.0.1", "27.2.2.2"}

	cachedEndpointIPs := IPIdentityCache.LookupByIdentity(29)
	sort.Strings(cachedEndpointIPs)
	c.Assert(cachedEndpointIPs, checker.DeepEquals, expectedIPList)

	namedPortsChanged = IPIdentityCache.Delete("27.2.2.2", source.KVStore)
	c.Assert(namedPortsChanged, Equals, false)

	expectedIPList = []string{"127.0.0.1"}

	cachedEndpointIPs = IPIdentityCache.LookupByIdentity(29)
	c.Assert(cachedEndpointIPs, checker.DeepEquals, expectedIPList)

	cachedIdentity, exists = IPIdentityCache.LookupByIP("127.0.0.1")
	c.Assert(exists, Equals, true)
	c.Assert(cachedIdentity.ID, Equals, identityPkg.NumericIdentity(29))

	cachedIdentity, exists = IPIdentityCache.LookupByPrefix("127.0.0.1/32")
	c.Assert(exists, Equals, true)
	c.Assert(cachedIdentity.ID, Equals, identityPkg.NumericIdentity(29))

	IPIdentityCache.Delete("127.0.0.1", source.KVStore)

	ips = IPIdentityCache.LookupByIdentity(29)
	c.Assert(ips, IsNil)

	_, exists = IPIdentityCache.LookupByPrefix("127.0.0.1/32")
	c.Assert(exists, Equals, false)

	// Clean up.
	for index := range endpointIPs {
		namedPortsChanged = IPIdentityCache.Delete(endpointIPs[index], source.KVStore)
		npm = IPIdentityCache.GetNamedPorts()
		c.Assert(npm, NotNil)
		log.Infof("Named ports after Delete %d: %v", index, npm)
		// 2nd delete removes named port mapping, as remaining IPs have an already deleted ID (29)
		c.Assert(namedPortsChanged, Equals, index == 1)

		_, exists = IPIdentityCache.LookupByIP(endpointIPs[index])
		c.Assert(exists, Equals, false)

		ips = IPIdentityCache.LookupByIdentity(identities[index])
		c.Assert(ips, IsNil)
	}

	c.Assert(len(IPIdentityCache.ipToIdentityCache), Equals, 1)
	c.Assert(len(IPIdentityCache.identityToIPCache), Equals, 1)

	namedPortsChanged = IPIdentityCache.Delete(endpointIP2, source.Kubernetes)
	c.Assert(namedPortsChanged, Equals, true)
	npm = IPIdentityCache.GetNamedPorts()
	c.Assert(npm.Len(), Equals, 0)
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
			"http": types.PortProto{Port: 80, Proto: uint8(u8proto.TCP)},
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
			NodeIDHandler:     &mockNodeIDHandler{},
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
	newID Identity, encryptKey uint8, _ uint16, k8sMeta *K8sMetadata) {

	switch modType {
	case Upsert:
		dl.entries[cidrCluster.String()] = newID.ID
	default:
		// Ignore, for simplicity we just clear the cache every time
	}
}

func (dl *dummyListener) OnIPIdentityCacheGC() {}

func (dl *dummyListener) ExpectMapping(c *C, targetIP string, targetIdentity identityPkg.NumericIdentity) {
	// Identity lookup directly shows the expected mapping
	identity, exists := dl.ipc.LookupByPrefix(targetIP)
	c.Assert(exists, Equals, true)
	c.Assert(identity.ID, Equals, targetIdentity)

	// Dump reliably supplies the IP once and only the pod identity.
	dl.entries = make(map[string]identityPkg.NumericIdentity)
	dl.ipc.DumpToListenerLocked(dl)
	c.Assert(dl.entries, checker.DeepEquals,
		map[string]identityPkg.NumericIdentity{
			targetIP: targetIdentity,
		})
}

func (s *IPCacheTestSuite) TestIPCacheShadowing(c *C) {
	endpointIP := "10.0.0.15"
	cidrOverlap := "10.0.0.15/32"
	epIdentity := (identityPkg.NumericIdentity(68))
	cidrIdentity := (identityPkg.NumericIdentity(202))
	ipc := IPIdentityCache

	// Assure sane state at start.
	c.Assert(ipc.ipToIdentityCache, checker.DeepEquals, map[string]Identity{})
	c.Assert(ipc.identityToIPCache, checker.DeepEquals, map[identityPkg.NumericIdentity]map[string]struct{}{})

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
	ipcache.ExpectMapping(c, cidrOverlap, epIdentity)

	// Deleting pod identity shows that cidr identity is now used.
	ipc.Delete(endpointIP, source.KVStore)
	ipcache.ExpectMapping(c, cidrOverlap, cidrIdentity)

	// Reinsert of pod IP should shadow the CIDR identity again.
	ipc.Upsert(endpointIP, nil, 0, nil, Identity{
		ID:     epIdentity,
		Source: source.KVStore,
	})
	ipcache.ExpectMapping(c, cidrOverlap, epIdentity)

	// Deletion of the shadowed identity should not change the output.
	ipc.Delete(cidrOverlap, source.Generated)
	ipcache.ExpectMapping(c, cidrOverlap, epIdentity)

	// Clean up
	ipc.Delete(endpointIP, source.KVStore)
	_, exists := ipc.LookupByPrefix(cidrOverlap)
	c.Assert(exists, Equals, false)
}

type mockNodeIDHandler struct{}

func (m *mockNodeIDHandler) AllocateNodeID(_ net.IP) uint16 {
	return 0
}

func (m *mockNodeIDHandler) GetNodeIP(_ uint16) string {
	return ""
}
