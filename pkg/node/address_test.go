// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package node

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	. "github.com/cilium/checkmate"

	"github.com/cilium/cilium/pkg/checker"
	"github.com/cilium/cilium/pkg/cidr"
)

// Hook up gocheck into the "go test" runner.
func Test(t *testing.T) {
	TestingT(t)
}

type NodeSuite struct{}

var _ = Suite(&NodeSuite{})

func (s *NodeSuite) TearDownTest(c *C) {
	Uninitialize()
}

// This also provides cover for RestoreHostIPs.
func (s *NodeSuite) Test_chooseHostIPsToRestore(c *C) {
	tests := []struct {
		name            string
		ipv6            bool
		fromK8s, fromFS net.IP
		cidr            *cidr.CIDR
		expect          net.IP
		err             error
	}{
		{
			name:    "restore IP from fs (both provided)",
			ipv6:    false,
			fromK8s: net.ParseIP("192.0.2.127"),
			fromFS:  net.ParseIP("192.0.2.255"),
			cidr:    cidr.MustParseCIDR("192.0.2.0/24"),
			expect:  net.ParseIP("192.0.2.255"),
			err:     errMismatch,
		},
		{
			name:   "restore IP from fs",
			ipv6:   false,
			fromFS: net.ParseIP("192.0.2.255"),
			cidr:   cidr.MustParseCIDR("192.0.2.0/24"),
			expect: net.ParseIP("192.0.2.255"),
			err:    nil,
		},
		{
			name:    "restore IP from k8s",
			ipv6:    false,
			fromK8s: net.ParseIP("192.0.2.127"),
			cidr:    cidr.MustParseCIDR("192.0.2.0/24"),
			expect:  net.ParseIP("192.0.2.127"),
			err:     nil,
		},
		{
			name:    "IP not part of CIDR",
			ipv6:    false,
			fromK8s: net.ParseIP("192.0.2.127"),
			cidr:    cidr.MustParseCIDR("192.1.2.0/24"),
			expect:  net.ParseIP("192.0.2.127"),
			err:     errDoesNotBelong,
		},
		{
			name: "no IPs to restore",
			ipv6: false,
			err:  nil,
		},
		{
			name:    "restore IP from fs (both provided)",
			ipv6:    true,
			fromK8s: net.ParseIP("ff02::127"),
			fromFS:  net.ParseIP("ff02::255"),
			cidr:    cidr.MustParseCIDR("ff02::/64"),
			expect:  net.ParseIP("ff02::255"),
			err:     errMismatch,
		},
		{
			name:   "restore IP from fs",
			ipv6:   true,
			fromFS: net.ParseIP("ff02::255"),
			cidr:   cidr.MustParseCIDR("ff02::/64"),
			expect: net.ParseIP("ff02::255"),
			err:    nil,
		},
		{
			name:    "restore IP from k8s",
			ipv6:    true,
			fromK8s: net.ParseIP("ff02::127"),
			cidr:    cidr.MustParseCIDR("ff02::/64"),
			expect:  net.ParseIP("ff02::127"),
			err:     nil,
		},
		{
			name: "no IPs to restore",
			ipv6: true,
			err:  nil,
		},
	}
	for _, tt := range tests {
		c.Log("Test: " + tt.name)
		got, err := chooseHostIPsToRestore(tt.ipv6, tt.fromK8s, tt.fromFS, []*cidr.CIDR{tt.cidr})
		c.Assert(err, checker.DeepEquals, tt.err)
		c.Assert(got, checker.DeepEquals, tt.expect)
	}
}

func (s *NodeSuite) Test_getCiliumHostIPsFromFile(c *C) {
	tmpDir := c.MkDir()
	allIPsCorrect := filepath.Join(tmpDir, "node_config.h")
	f, err := os.Create(allIPsCorrect)
	c.Assert(err, IsNil)
	defer f.Close()
	fmt.Fprintf(f, `/*
 cilium.v6.external.str fd01::b
 cilium.v6.internal.str f00d::a00:0:0:a4ad
 cilium.v6.nodeport.str []

 cilium.v4.external.str 192.168.60.11
 cilium.v4.internal.str 10.0.0.2
 cilium.v4.nodeport.str []

 cilium.v6.internal.raw 0xf0, 0xd, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0xa, 0x0, 0x0, 0x0, 0x0, 0x0, 0xa4, 0xad
 cilium.v4.internal.raw 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0xff, 0xff, 0xa, 0x0, 0x0, 0x2
 */

#define ENABLE_IPV4 1
#define ROUTER_IP 0xf0, 0xd, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0xa, 0x0, 0x0, 0x0, 0x0, 0x0, 0xa4, 0xad
#define IPV4_GATEWAY 0x100000a
#define IPV4_LOOPBACK 0x5dd0000a
#define IPV4_MASK 0xffff
#define HOST_IP 0xfd, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0xb
#define HOST_ID 1
#define WORLD_ID 2
#define CILIUM_LB_MAP_MAX_ENTRIES 65536
#define TUNNEL_ENDPOINT_MAP_SIZE 65536
#define ENDPOINTS_MAP_SIZE 65535
#define LPM_MAP_SIZE 16384
#define POLICY_MAP_SIZE 16384
#define IPCACHE_MAP_SIZE 512000
#define POLICY_PROG_MAP_SIZE 65535
#define TRACE_PAYLOAD_LEN 128ULL
#ifndef CILIUM_NET_MAC
#define CILIUM_NET_MAC { .addr = {0x26,0x11,0x70,0xcc,0xca,0x0c}}
#endif /* CILIUM_NET_MAC */
#define HOST_IFINDEX 356
#define HOST_IFINDEX_MAC { .addr = {0x3e,0x28,0xb4,0x4b,0x95,0x25}}
#define ENCAP_IFINDEX 358
`)

	type args struct {
		nodeConfig string
	}
	tests := []struct {
		name            string
		args            args
		wantIpv4GW      net.IP
		wantIpv6Router  net.IP
		wantIpv6Address net.IP
	}{
		{
			name: "every-ip-correct",
			args: args{
				nodeConfig: allIPsCorrect,
			},
			wantIpv4GW:      net.ParseIP("10.0.0.2"),
			wantIpv6Router:  net.ParseIP("f00d::a00:0:0:a4ad"),
			wantIpv6Address: net.ParseIP("fd01::b"),
		},
		{
			name: "file-not-present",
			args: args{
				nodeConfig: "",
			},
			wantIpv4GW:     nil,
			wantIpv6Router: nil,
		},
	}
	for _, tt := range tests {
		gotIpv4GW, gotIpv6Router := getCiliumHostIPsFromFile(tt.args.nodeConfig)
		if !reflect.DeepEqual(gotIpv4GW, tt.wantIpv4GW) {
			c.Assert(gotIpv4GW, checker.DeepEquals, tt.wantIpv4GW)
		}
		if !reflect.DeepEqual(gotIpv6Router, tt.wantIpv6Router) {
			c.Assert(gotIpv6Router, checker.DeepEquals, tt.wantIpv6Router)
		}
	}
}
