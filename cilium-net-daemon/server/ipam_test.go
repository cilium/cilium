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

func (s *DaemonSuite) TestAllocateIPsOK(c *C) {
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

	s.d.OnAllocateIPs = func(containerID string) (*types.IPAMConfig, error) {
		c.Assert(containerID, Equals, "11b3354cca51cf41ef05f338ec6c1016d03f9496ff701b6060b649248ae07523")
		return &ipamConfig, nil
	}

	ipamConfigReceived, err := s.c.AllocateIPs("11b3354cca51cf41ef05f338ec6c1016d03f9496ff701b6060b649248ae07523")
	c.Assert(err, Equals, nil)
	c.Assert(ipamConfig, DeepEquals, *ipamConfigReceived)
}

func (s *DaemonSuite) TestAllocateIPsFail(c *C) {
	s.d.OnAllocateIPs = func(containerID string) (*types.IPAMConfig, error) {
		c.Assert(containerID, Equals, "11b3354cca51cf41ef05f338ec6c1016d03f9496ff701b6060b649248ae07523")
		return nil, errors.New("IP allocator full")
	}

	_, err := s.c.AllocateIPs("11b3354cca51cf41ef05f338ec6c1016d03f9496ff701b6060b649248ae07523")
	c.Assert(strings.Contains(err.Error(), "IP allocator full"), Equals, true)
}

func (s *DaemonSuite) TestReleaseIPsOK(c *C) {
	s.d.OnReleaseIPs = func(containerID string) error {
		c.Assert(containerID, Equals, "11b3354cca51cf41ef05f338ec6c1016d03f9496ff701b6060b649248ae07523")
		return nil
	}

	err := s.c.ReleaseIPs("11b3354cca51cf41ef05f338ec6c1016d03f9496ff701b6060b649248ae07523")
	c.Assert(err, Equals, nil)
}

func (s *DaemonSuite) TestReleaseIPsFail(c *C) {
	s.d.OnReleaseIPs = func(containerID string) error {
		c.Assert(containerID, Equals, "11b3354cca51cf41ef05f338ec6c1016d03f9496ff701b6060b649248ae07523")
		return errors.New("IP allocator didn't found container")
	}

	err := s.c.ReleaseIPs("11b3354cca51cf41ef05f338ec6c1016d03f9496ff701b6060b649248ae07523")
	c.Assert(strings.Contains(err.Error(), "IP allocator didn't found container"), Equals, true)
}
