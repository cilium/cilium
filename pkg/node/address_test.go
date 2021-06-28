// Copyright 2016-2018 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// +build !privileged_tests

package node

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/cilium/cilium/pkg/checker"
	"github.com/cilium/cilium/pkg/cidr"

	. "gopkg.in/check.v1"
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

func (s *NodeSuite) TestMaskCheck(c *C) {
	InitDefaultPrefix("")

	allocCIDR := cidr.MustParseCIDR("1.1.1.1/16")
	SetIPv4AllocRange(allocCIDR)
	SetInternalIPv4Router(allocCIDR.IP)
	c.Assert(IsHostIPv4(GetInternalIPv4Router()), Equals, true)
	c.Assert(IsHostIPv4(GetIPv4()), Equals, true)
	c.Assert(IsHostIPv6(GetIPv6()), Equals, true)
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
		got, err := chooseHostIPsToRestore(tt.ipv6, tt.fromK8s, tt.fromFS, tt.cidr)
		if tt.expect == nil {
			// If we don't expect to change it, set it to what's currently the
			// router IP.
			if tt.ipv6 {
				tt.expect = GetIPv6Router()
			} else {
				tt.expect = GetInternalIPv4Router()
			}
		}
		c.Assert(err, checker.DeepEquals, tt.err)
		if tt.ipv6 {
			c.Assert(got, checker.DeepEquals, tt.expect)
		} else {
			c.Assert(got, checker.DeepEquals, tt.expect)
		}
	}
}

func (s *NodeSuite) Test_getCiliumHostIPsFromFile(c *C) {
	tmpDir := c.MkDir()
	allIPsCorrect := filepath.Join(tmpDir, "node_config.h")
	f, err := os.Create(allIPsCorrect)
	c.Assert(err, IsNil)
	defer f.Close()
	fmt.Fprintf(f, `/*
 * Node-IPv6: fd01::b
 * Router-IPv6: f00d::a00:0:0:a4ad
 * Host-IPv4: 10.0.0.1
 */

#define ENABLE_IPV4 1
#define ROUTER_IP 0xf0, 0xd, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0xa, 0x0, 0x0, 0x0, 0x0, 0x0, 0xa4, 0xad
#define IPV4_GATEWAY 0x100000a
#define IPV4_LOOPBACK 0x5dd0000a
#define IPV4_MASK 0xffff
#define NAT46_PREFIX { .addr = { 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0xff, 0xff, 0x0, 0x0, 0x0, 0x0 } }
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
#define ENCAP_VXLAN 1
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
			wantIpv4GW:      net.ParseIP("10.0.0.1"),
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
