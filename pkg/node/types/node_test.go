// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build !privileged_tests

package types

import (
	"net"
	"testing"

	. "gopkg.in/check.v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cilium/cilium/pkg/annotation"
	"github.com/cilium/cilium/pkg/checker"
	"github.com/cilium/cilium/pkg/cidr"
	ipamTypes "github.com/cilium/cilium/pkg/ipam/types"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/node/addressing"
	"github.com/cilium/cilium/pkg/source"
)

// Hook up gocheck into the "go test" runner.
func Test(t *testing.T) {
	TestingT(t)
}

type NodeSuite struct{}

var _ = Suite(&NodeSuite{})

func (s *NodeSuite) TestGetNodeIP(c *C) {
	n := Node{
		Name: "node-1",
		IPAddresses: []Address{
			{IP: net.ParseIP("192.0.2.3"), Type: addressing.NodeExternalIP},
		},
	}
	ip := n.GetNodeIP(false)
	// Return the only IP present
	c.Assert(ip.Equal(net.ParseIP("192.0.2.3")), Equals, true)

	n.IPAddresses = append(n.IPAddresses, Address{IP: net.ParseIP("192.0.2.3"), Type: addressing.NodeExternalIP})
	ip = n.GetNodeIP(false)
	// The next priority should be NodeExternalIP
	c.Assert(ip.Equal(net.ParseIP("192.0.2.3")), Equals, true)

	n.IPAddresses = append(n.IPAddresses, Address{IP: net.ParseIP("198.51.100.2"), Type: addressing.NodeInternalIP})
	ip = n.GetNodeIP(false)
	// The next priority should be NodeInternalIP
	c.Assert(ip.Equal(net.ParseIP("198.51.100.2")), Equals, true)

	n.IPAddresses = append(n.IPAddresses, Address{IP: net.ParseIP("2001:DB8::1"), Type: addressing.NodeExternalIP})
	ip = n.GetNodeIP(true)
	// The next priority should be NodeExternalIP and IPv6
	c.Assert(ip.Equal(net.ParseIP("2001:DB8::1")), Equals, true)

	n.IPAddresses = append(n.IPAddresses, Address{IP: net.ParseIP("2001:DB8::2"), Type: addressing.NodeInternalIP})
	ip = n.GetNodeIP(true)
	// The next priority should be NodeInternalIP and IPv6
	c.Assert(ip.Equal(net.ParseIP("2001:DB8::2")), Equals, true)

	n.IPAddresses = append(n.IPAddresses, Address{IP: net.ParseIP("198.51.100.2"), Type: addressing.NodeInternalIP})
	ip = n.GetNodeIP(false)
	// Should still return NodeInternalIP and IPv4
	c.Assert(ip.Equal(net.ParseIP("198.51.100.2")), Equals, true)

}

func (s *NodeSuite) TestGetIPByType(c *C) {
	n := Node{
		Name: "node-1",
		IPAddresses: []Address{
			{IP: net.ParseIP("192.0.2.3"), Type: addressing.NodeExternalIP},
		},
	}

	ip := n.GetIPByType(addressing.NodeInternalIP, false)
	c.Assert(ip, IsNil)
	ip = n.GetIPByType(addressing.NodeInternalIP, true)
	c.Assert(ip, IsNil)

	ip = n.GetIPByType(addressing.NodeExternalIP, false)
	c.Assert(ip.Equal(net.ParseIP("192.0.2.3")), Equals, true)
	ip = n.GetIPByType(addressing.NodeExternalIP, true)
	c.Assert(ip, IsNil)

	n = Node{
		Name: "node-2",
		IPAddresses: []Address{
			{IP: net.ParseIP("f00b::1"), Type: addressing.NodeCiliumInternalIP},
		},
	}

	ip = n.GetIPByType(addressing.NodeExternalIP, false)
	c.Assert(ip, IsNil)
	ip = n.GetIPByType(addressing.NodeExternalIP, true)
	c.Assert(ip, IsNil)

	ip = n.GetIPByType(addressing.NodeCiliumInternalIP, false)
	c.Assert(ip, IsNil)
	ip = n.GetIPByType(addressing.NodeCiliumInternalIP, true)
	c.Assert(ip.Equal(net.ParseIP("f00b::1")), Equals, true)

	n = Node{
		Name: "node-3",
		IPAddresses: []Address{
			{IP: net.ParseIP("192.42.0.3"), Type: addressing.NodeExternalIP},
			{IP: net.ParseIP("f00d::1"), Type: addressing.NodeExternalIP},
		},
	}

	ip = n.GetIPByType(addressing.NodeInternalIP, false)
	c.Assert(ip, IsNil)
	ip = n.GetIPByType(addressing.NodeInternalIP, true)
	c.Assert(ip, IsNil)

	ip = n.GetIPByType(addressing.NodeExternalIP, false)
	c.Assert(ip.Equal(net.ParseIP("192.42.0.3")), Equals, true)
	ip = n.GetIPByType(addressing.NodeExternalIP, true)
	c.Assert(ip.Equal(net.ParseIP("f00d::1")), Equals, true)
}

func (s *NodeSuite) TestParseCiliumNode(c *C) {
	nodeResource := &ciliumv2.CiliumNode{
		ObjectMeta: metav1.ObjectMeta{Name: "foo", Namespace: "default"},
		Spec: ciliumv2.NodeSpec{
			Addresses: []ciliumv2.NodeAddress{
				{Type: addressing.NodeInternalIP, IP: "2.2.2.2"},
				{Type: addressing.NodeExternalIP, IP: "3.3.3.3"},
				{Type: addressing.NodeInternalIP, IP: "c0de::1"},
				{Type: addressing.NodeExternalIP, IP: "c0de::2"},
			},
			Encryption: ciliumv2.EncryptionSpec{
				Key: 10,
			},
			IPAM: ipamTypes.IPAMSpec{
				PodCIDRs: []string{
					"10.10.0.0/16",
					"c0de::/96",
					"10.20.0.0/16",
					"c0fe::/96",
				},
			},
			HealthAddressing: ciliumv2.HealthAddressingSpec{
				IPv4: "1.1.1.1",
				IPv6: "c0de::1",
			},
			IngressAddressing: ciliumv2.AddressPair{
				IPV4: "1.1.1.2",
				IPV6: "c0de::2",
			},
			NodeIdentity: uint64(12345),
		},
	}

	n := ParseCiliumNode(nodeResource)
	c.Assert(n, checker.DeepEquals, Node{
		Name:   "foo",
		Source: source.CustomResource,
		IPAddresses: []Address{
			{Type: addressing.NodeInternalIP, IP: net.ParseIP("2.2.2.2")},
			{Type: addressing.NodeExternalIP, IP: net.ParseIP("3.3.3.3")},
			{Type: addressing.NodeInternalIP, IP: net.ParseIP("c0de::1")},
			{Type: addressing.NodeExternalIP, IP: net.ParseIP("c0de::2")},
		},
		EncryptionKey:           uint8(10),
		IPv4AllocCIDR:           cidr.MustParseCIDR("10.10.0.0/16"),
		IPv6AllocCIDR:           cidr.MustParseCIDR("c0de::/96"),
		IPv4SecondaryAllocCIDRs: []*cidr.CIDR{cidr.MustParseCIDR("10.20.0.0/16")},
		IPv6SecondaryAllocCIDRs: []*cidr.CIDR{cidr.MustParseCIDR("c0fe::/96")},
		IPv4HealthIP:            net.ParseIP("1.1.1.1"),
		IPv6HealthIP:            net.ParseIP("c0de::1"),
		IPv4IngressIP:           net.ParseIP("1.1.1.2"),
		IPv6IngressIP:           net.ParseIP("c0de::2"),
		NodeIdentity:            uint32(12345),
	})
}

func (s *NodeSuite) TestNode_ToCiliumNode(c *C) {
	nodeResource := Node{
		Name:   "foo",
		Source: source.CustomResource,
		IPAddresses: []Address{
			{Type: addressing.NodeInternalIP, IP: net.ParseIP("2.2.2.2")},
			{Type: addressing.NodeExternalIP, IP: net.ParseIP("3.3.3.3")},
			{Type: addressing.NodeInternalIP, IP: net.ParseIP("c0de::1")},
			{Type: addressing.NodeExternalIP, IP: net.ParseIP("c0de::2")},
		},
		EncryptionKey:           uint8(10),
		IPv4AllocCIDR:           cidr.MustParseCIDR("10.10.0.0/16"),
		IPv6AllocCIDR:           cidr.MustParseCIDR("c0de::/96"),
		IPv4SecondaryAllocCIDRs: []*cidr.CIDR{cidr.MustParseCIDR("10.20.0.0/16")},
		IPv6SecondaryAllocCIDRs: []*cidr.CIDR{cidr.MustParseCIDR("c0fe::/96")},
		IPv4HealthIP:            net.ParseIP("1.1.1.1"),
		IPv6HealthIP:            net.ParseIP("c0de::1"),
		IPv4IngressIP:           net.ParseIP("1.1.1.2"),
		IPv6IngressIP:           net.ParseIP("c0de::2"),
		NodeIdentity:            uint32(12345),
		WireguardPubKey:         "6kiIGGPvMiadJ1brWTVfSGXheE3e3k5GjDTxfjMLYx8=",
	}

	n := nodeResource.ToCiliumNode()
	c.Assert(n, checker.DeepEquals, &ciliumv2.CiliumNode{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "foo",
			Namespace: "",
			Annotations: map[string]string{
				annotation.WireguardPubKey: "6kiIGGPvMiadJ1brWTVfSGXheE3e3k5GjDTxfjMLYx8=",
			},
		},
		Spec: ciliumv2.NodeSpec{
			Addresses: []ciliumv2.NodeAddress{
				{Type: addressing.NodeInternalIP, IP: "2.2.2.2"},
				{Type: addressing.NodeExternalIP, IP: "3.3.3.3"},
				{Type: addressing.NodeInternalIP, IP: "c0de::1"},
				{Type: addressing.NodeExternalIP, IP: "c0de::2"},
			},
			Encryption: ciliumv2.EncryptionSpec{
				Key: 10,
			},
			IPAM: ipamTypes.IPAMSpec{
				PodCIDRs: []string{
					"10.10.0.0/16",
					"c0de::/96",
					"10.20.0.0/16",
					"c0fe::/96",
				},
			},
			HealthAddressing: ciliumv2.HealthAddressingSpec{
				IPv4: "1.1.1.1",
				IPv6: "c0de::1",
			},
			IngressAddressing: ciliumv2.AddressPair{
				IPV4: "1.1.1.2",
				IPV6: "c0de::2",
			},
			NodeIdentity: uint64(12345),
		},
	})
}
