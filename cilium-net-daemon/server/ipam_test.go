package server

import (
	"errors"
	"net"
	"strings"

	"github.com/noironetworks/cilium-net/common"
	"github.com/noironetworks/cilium-net/common/types"

	libnetworktypes "github.com/docker/libnetwork/types"
	. "gopkg.in/check.v1"
)

func (s *DaemonSuite) TestAllocateIPOK(c *C) {
	ipamConfig := types.IPAMConfig{
		IP6: &types.IPConfig{
			Gateway: NodeAddr,
			IP:      net.IPNet{IP: EpAddr, Mask: common.NodeIPv6Mask},
			Routes: []types.Route{
				types.Route{
					Destination: net.IPNet{IP: net.IPv6zero, Mask: net.CIDRMask(0, 128)},
					NextHop:     nil,
					Type:        libnetworktypes.CONNECTED,
				},
			},
		},
	}

	ipamReq := types.IPAMReq{ContainerID: "11b3354cca51cf41ef05f338ec6c1016d03f9496ff701b6060b649248ae07523"}

	s.d.OnAllocateIP = func(ipamType types.IPAMType, opts types.IPAMReq) (*types.IPAMConfig, error) {
		c.Assert(ipamType, Equals, types.CNIIPAMType)
		c.Assert(opts, Equals, ipamReq)
		return &ipamConfig, nil
	}

	ipamConfigReceived, err := s.c.AllocateIP(types.CNIIPAMType, ipamReq)
	c.Assert(err, Equals, nil)
	c.Assert(ipamConfig, DeepEquals, *ipamConfigReceived)
}

func (s *DaemonSuite) TestAllocateIPFail(c *C) {
	ipamReq := types.IPAMReq{ContainerID: "11b3354cca51cf41ef05f338ec6c1016d03f9496ff701b6060b649248ae07523"}

	s.d.OnAllocateIP = func(ipamType types.IPAMType, opts types.IPAMReq) (*types.IPAMConfig, error) {
		c.Assert(ipamType, Equals, types.CNIIPAMType)
		c.Assert(opts, Equals, ipamReq)
		return nil, errors.New("IP allocator full")
	}

	_, err := s.c.AllocateIP(types.CNIIPAMType, ipamReq)
	c.Assert(strings.Contains(err.Error(), "IP allocator full"), Equals, true)
}

func (s *DaemonSuite) TestReleaseIPOK(c *C) {
	ipamReq := types.IPAMReq{ContainerID: "11b3354cca51cf41ef05f338ec6c1016d03f9496ff701b6060b649248ae07523"}

	s.d.OnReleaseIP = func(ipamType types.IPAMType, opts types.IPAMReq) error {
		c.Assert(ipamType, Equals, types.CNIIPAMType)
		c.Assert(opts, Equals, ipamReq)
		return nil
	}

	err := s.c.ReleaseIP(types.CNIIPAMType, ipamReq)
	c.Assert(err, Equals, nil)
}

func (s *DaemonSuite) TestReleaseIPFail(c *C) {
	ipamReq := types.IPAMReq{ContainerID: "11b3354cca51cf41ef05f338ec6c1016d03f9496ff701b6060b649248ae07523"}

	s.d.OnReleaseIP = func(ipamType types.IPAMType, opts types.IPAMReq) error {
		c.Assert(ipamType, Equals, types.CNIIPAMType)
		c.Assert(opts, Equals, ipamReq)
		return errors.New("IP allocator didn't found container")
	}

	err := s.c.ReleaseIP(types.CNIIPAMType, ipamReq)
	c.Assert(strings.Contains(err.Error(), "IP allocator didn't found container"), Equals, true)
}
