// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package agent

import (
	"context"
	"net"
	"testing"

	. "github.com/cilium/checkmate"
	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/cilium/cilium/pkg/checker"
	"github.com/cilium/cilium/pkg/cidr"
	iputil "github.com/cilium/cilium/pkg/ip"
	"github.com/cilium/cilium/pkg/ipcache"
	"github.com/cilium/cilium/pkg/source"
)

type AgentSuite struct{}

var _ = Suite(&AgentSuite{})

func Test(t *testing.T) {
	TestingT(t)
}

type fakeWgClient struct{}

func (f *fakeWgClient) Close() error {
	return nil
}

func (f *fakeWgClient) Devices() ([]*wgtypes.Device, error) {
	return nil, nil
}

func (f *fakeWgClient) Device(name string) (*wgtypes.Device, error) {
	return nil, unix.ENODEV
}

func (f *fakeWgClient) ConfigureDevice(name string, cfg wgtypes.Config) error {
	return nil
}

var (
	k8s1NodeName = "k8s1"
	k8s1PubKey   = "YKQF5gwcQrsZWzxGd4ive+IeCOXjPN4aS9jiMSpAlCg="
	k8s1NodeIPv4 = net.ParseIP("192.168.60.11")
	k8s1NodeIPv6 = net.ParseIP("fd01::b")

	k8s2NodeName = "k8s2"
	k8s2PubKey   = "lH+Xsa0JClu1syeBVbXN0LZNQVB6rTPBzbzWOHwQLW4="
	k8s2NodeIPv4 = net.ParseIP("192.168.60.12")
	k8s2NodeIPv6 = net.ParseIP("fd01::c")

	pod1IPv4Str = "10.0.0.1"
	pod1IPv4    = iputil.IPToPrefix(net.ParseIP(pod1IPv4Str))
	pod1IPv6Str = "fd00::1"
	pod1IPv6    = iputil.IPToPrefix(net.ParseIP(pod1IPv6Str))
	pod2IPv4Str = "10.0.0.2"
	pod2IPv4    = iputil.IPToPrefix(net.ParseIP(pod2IPv4Str))
	pod2IPv6Str = "fd00::2"
	pod2IPv6    = iputil.IPToPrefix(net.ParseIP(pod2IPv6Str))
	pod3IPv4Str = "10.0.0.3"
	pod3IPv4    = iputil.IPToPrefix(net.ParseIP(pod3IPv4Str))
	pod3IPv6Str = "fd00::3"
	pod3IPv6    = iputil.IPToPrefix(net.ParseIP(pod3IPv6Str))
)

func containsIP(allowedIPs []net.IPNet, ipnet *net.IPNet) bool {
	for _, allowedIP := range allowedIPs {
		if cidr.Equal(&allowedIP, ipnet) {
			return true
		}
	}
	return false
}

func newTestAgent(ctx context.Context) (*Agent, *ipcache.IPCache) {
	ipCache := ipcache.NewIPCache(&ipcache.Configuration{
		Context:       ctx,
		NodeIDHandler: &mockNodeHandler{},
	})
	wgAgent := &Agent{
		wgClient:         &fakeWgClient{},
		ipCache:          ipCache,
		listenPort:       listenPort,
		peerByNodeName:   map[string]*peerConfig{},
		nodeNameByNodeIP: map[string]string{},
		nodeNameByPubKey: map[wgtypes.Key]string{},
	}
	ipCache.AddListener(wgAgent)
	return wgAgent, ipCache
}

func (a *AgentSuite) TestAgent_PeerConfig(c *C) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	wgAgent, ipCache := newTestAgent(ctx)
	defer ipCache.Shutdown()

	// Test that IPCache updates before UpdatePeer are handled correctly
	ipCache.Upsert(pod1IPv4Str, k8s1NodeIPv4, 0, nil, ipcache.Identity{ID: 1, Source: source.Kubernetes})
	ipCache.Upsert(pod1IPv6Str, k8s1NodeIPv6, 0, nil, ipcache.Identity{ID: 1, Source: source.Kubernetes})
	ipCache.Upsert(pod2IPv4Str, k8s1NodeIPv4, 0, nil, ipcache.Identity{ID: 2, Source: source.Kubernetes})
	ipCache.Upsert(pod2IPv6Str, k8s1NodeIPv6, 0, nil, ipcache.Identity{ID: 2, Source: source.Kubernetes})

	err := wgAgent.UpdatePeer(k8s1NodeName, k8s1PubKey, k8s1NodeIPv4, k8s1NodeIPv6)
	c.Assert(err, IsNil)

	k8s1 := wgAgent.peerByNodeName[k8s1NodeName]
	c.Assert(k8s1, NotNil)
	c.Assert(k8s1.nodeIPv4, checker.DeepEquals, k8s1NodeIPv4)
	c.Assert(k8s1.nodeIPv6, checker.DeepEquals, k8s1NodeIPv6)
	c.Assert(k8s1.pubKey.String(), Equals, k8s1PubKey)
	c.Assert(k8s1.allowedIPs, HasLen, 4)
	c.Assert(containsIP(k8s1.allowedIPs, pod1IPv4), Equals, true)
	c.Assert(containsIP(k8s1.allowedIPs, pod1IPv6), Equals, true)
	c.Assert(containsIP(k8s1.allowedIPs, pod2IPv4), Equals, true)
	c.Assert(containsIP(k8s1.allowedIPs, pod2IPv6), Equals, true)

	// Tests that IPCache updates are blocked by a concurrent UpdatePeer.
	// We test this by issuing an UpdatePeer request while holding
	// the agent lock (meaning the UpdatePeer call will first take the IPCache
	// lock and then wait for the agent lock to become available),
	// then issuing an IPCache update (which will be blocked because
	// UpdatePeer already holds the IPCache lock), and then releasing the
	// agent lock to allow both operations to proceed.
	wgAgent.Lock()

	agentUpdated := make(chan struct{})
	agentUpdatePending := make(chan struct{})
	go func() {
		close(agentUpdatePending)
		err = wgAgent.UpdatePeer(k8s2NodeName, k8s2PubKey, k8s2NodeIPv4, k8s2NodeIPv6)
		c.Assert(err, IsNil)
		close(agentUpdated)
	}()

	// wait for the above goroutine to be scheduled
	<-agentUpdatePending

	ipCacheUpdated := make(chan struct{})
	ipCacheUpdatePending := make(chan struct{})
	go func() {
		close(ipCacheUpdatePending)
		// Insert pod3
		ipCache.Upsert(pod3IPv4Str, k8s2NodeIPv4, 0, nil, ipcache.Identity{ID: 3, Source: source.Kubernetes})
		ipCache.Upsert(pod3IPv6Str, k8s2NodeIPv6, 0, nil, ipcache.Identity{ID: 3, Source: source.Kubernetes})
		// Update pod2
		ipCache.Upsert(pod2IPv4Str, k8s1NodeIPv4, 0, nil, ipcache.Identity{ID: 22, Source: source.Kubernetes})
		ipCache.Upsert(pod2IPv6Str, k8s1NodeIPv6, 0, nil, ipcache.Identity{ID: 22, Source: source.Kubernetes})
		// Delete pod1
		ipCache.Delete(pod1IPv4Str, source.Kubernetes)
		ipCache.Delete(pod1IPv6Str, source.Kubernetes)
		close(ipCacheUpdated)
	}()

	// wait for the above goroutine to be scheduled
	<-ipCacheUpdatePending

	// At this point we know both goroutines have been scheduled. We assume
	// that they are now both blocked by checking they haven't closed the
	// channel yet. Thus once release the lock we expect them to make progress
	select {
	case <-agentUpdated:
		c.Fatal("agent update not blocked by agent lock")
	case <-ipCacheUpdated:
		c.Fatal("ipcache update not blocked by agent lock")
	default:
	}

	wgAgent.Unlock()

	// Ensure that both operations succeeded without a deadlock
	<-agentUpdated
	<-ipCacheUpdated

	k8s1 = wgAgent.peerByNodeName[k8s1NodeName]
	c.Assert(k8s1.nodeIPv4, checker.DeepEquals, k8s1NodeIPv4)
	c.Assert(k8s1.nodeIPv6, checker.DeepEquals, k8s1NodeIPv6)
	c.Assert(k8s1.pubKey.String(), Equals, k8s1PubKey)
	c.Assert(k8s1.allowedIPs, HasLen, 2)
	c.Assert(containsIP(k8s1.allowedIPs, pod2IPv4), Equals, true)
	c.Assert(containsIP(k8s1.allowedIPs, pod2IPv6), Equals, true)

	k8s2 := wgAgent.peerByNodeName[k8s2NodeName]
	c.Assert(k8s2.nodeIPv4, checker.DeepEquals, k8s2NodeIPv4)
	c.Assert(k8s2.nodeIPv6, checker.DeepEquals, k8s2NodeIPv6)
	c.Assert(k8s2.pubKey.String(), Equals, k8s2PubKey)
	c.Assert(k8s2.allowedIPs, HasLen, 2)
	c.Assert(containsIP(k8s2.allowedIPs, pod3IPv4), Equals, true)
	c.Assert(containsIP(k8s2.allowedIPs, pod3IPv6), Equals, true)

	// Tests that duplicate public keys are rejected (k8s2 imitates k8s1)
	err = wgAgent.UpdatePeer(k8s2NodeName, k8s1PubKey, k8s2NodeIPv4, k8s2NodeIPv6)
	c.Assert(err, ErrorMatches, "detected duplicate public key.*")

	// Node Deletion
	wgAgent.DeletePeer(k8s1NodeName)
	wgAgent.DeletePeer(k8s2NodeName)
	c.Assert(wgAgent.peerByNodeName, HasLen, 0)
	c.Assert(wgAgent.nodeNameByNodeIP, HasLen, 0)
	c.Assert(wgAgent.nodeNameByPubKey, HasLen, 0)
}

func (a *AgentSuite) TestAgent_PeerConfig_WithEncryptNode(c *C) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	wgAgent, ipCache := newTestAgent(ctx)
	wgAgent.nodeToNodeEncryption = true
	defer ipCache.Shutdown()

	ipCache.Upsert(pod1IPv4Str, k8s1NodeIPv4, 0, nil, ipcache.Identity{ID: 1, Source: source.Kubernetes})
	ipCache.Upsert(pod2IPv4Str, k8s1NodeIPv4, 0, nil, ipcache.Identity{ID: 2, Source: source.Kubernetes})

	err := wgAgent.UpdatePeer(k8s1NodeName, k8s1PubKey, k8s1NodeIPv4, k8s1NodeIPv6)
	c.Assert(err, IsNil)

	k8s1 := wgAgent.peerByNodeName[k8s1NodeName]
	c.Assert(k8s1, NotNil)
	c.Assert(k8s1.nodeIPv4, checker.DeepEquals, k8s1NodeIPv4)
	c.Assert(k8s1.nodeIPv6, checker.DeepEquals, k8s1NodeIPv6)
	c.Assert(k8s1.pubKey.String(), Equals, k8s1PubKey)
	c.Assert(k8s1.allowedIPs, HasLen, 4)
	c.Assert(containsIP(k8s1.allowedIPs, pod1IPv4), Equals, true)
	c.Assert(containsIP(k8s1.allowedIPs, pod2IPv4), Equals, true)
	c.Assert(containsIP(k8s1.allowedIPs, iputil.IPToPrefix(k8s1NodeIPv4)), Equals, true)
	c.Assert(containsIP(k8s1.allowedIPs, iputil.IPToPrefix(k8s1NodeIPv6)), Equals, true)
}

type mockNodeHandler struct{}

func (m *mockNodeHandler) AllocateNodeID(_ net.IP) uint16 {
	return 0
}

func (m *mockNodeHandler) GetNodeIP(_ uint16) string {
	return ""
}
