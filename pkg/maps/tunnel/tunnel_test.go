// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package tunnel

import (
	"net"
	"testing"

	. "github.com/cilium/checkmate"

	"github.com/cilium/ebpf/rlimit"

	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/testutils"
)

type TunnelMapTestSuite struct{}

var _ = Suite(&TunnelMapTestSuite{})

func Test(t *testing.T) {
	TestingT(t)
}

func (s *TunnelMapTestSuite) SetUpSuite(c *C) {
	testutils.PrivilegedTest(c)
	err := rlimit.RemoveMemlock()
	c.Assert(err, IsNil)
}

func (s *TunnelMapTestSuite) TestClusterAwareAddressing(c *C) {
	m := NewTunnelMap("test_cilium_tunnel_map")
	defer m.Unpin()

	err := m.OpenOrCreate()
	c.Assert(err, IsNil)

	prefix0 := cmtypes.MustParseAddrCluster("10.0.0.1")
	prefix1 := cmtypes.MustParseAddrCluster("10.0.0.1@1")
	endpoint0 := net.ParseIP("192.168.0.1")
	endpoint1 := net.ParseIP("192.168.1.1")

	// Test insertion with bare IP
	err = m.SetTunnelEndpoint(0, 0, prefix0, endpoint0)
	c.Assert(err, IsNil)

	// Test insertion with AddrCluster
	err = m.SetTunnelEndpoint(0, 0, prefix1, endpoint1)
	c.Assert(err, IsNil)

	// Test if tunnel map can distinguish prefix0 and prefix1
	ip0, err := m.GetTunnelEndpoint(prefix0)
	c.Assert(err, IsNil)
	c.Assert(ip0.Equal(endpoint0), Equals, true)

	ip1, err := m.GetTunnelEndpoint(prefix1)
	c.Assert(err, IsNil)
	c.Assert(ip1.Equal(endpoint1), Equals, true)

	// Delete prefix0 and check it deletes prefix0 correctly
	err = m.DeleteTunnelEndpoint(prefix0)
	c.Assert(err, IsNil)

	_, err = m.GetTunnelEndpoint(prefix0)
	c.Assert(err, NotNil)

	_, err = m.GetTunnelEndpoint(prefix1)
	c.Assert(err, IsNil)

	// Delete prefix0 and check it deletes prefix0 correctly
	err = m.DeleteTunnelEndpoint(prefix1)
	c.Assert(err, IsNil)

	_, err = m.GetTunnelEndpoint(prefix1)
	c.Assert(err, NotNil)
}
