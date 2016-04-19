package server

import (
	"errors"
	"net"
	"strconv"
	"strings"

	"github.com/noironetworks/cilium-net/common"
	"github.com/noironetworks/cilium-net/common/types"

	. "github.com/noironetworks/cilium-net/Godeps/_workspace/src/gopkg.in/check.v1"
)

var (
	EpAddr          = net.IP{0xbe, 0xef, 0xbe, 0xef, 0xbe, 0xef, 0xbe, 0xef, 0xaa, 0xaa, 0xaa, 0xaa, 0x11, 0x11, 0x11, 0x12}
	NodeAddr        = net.IP{0xbe, 0xef, 0xbe, 0xef, 0xbe, 0xef, 0xbe, 0xef, 0xaa, 0xaa, 0xaa, 0xaa, 0x11, 0x11, 0, 0}
	HardAddr        = types.MAC{0x01, 0x02, 0x03, 0x04, 0x05, 0x06}
	SecLabel uint32 = 0x200
)

func (s *DaemonSuite) TestEndpointCreateOK(c *C) {
	ep := types.Endpoint{
		LXCMAC:        HardAddr,
		LXCIP:         EpAddr,
		NodeMAC:       HardAddr,
		NodeIP:        NodeAddr,
		IfName:        "ifname",
		DockerNetwork: "dockernetwork",
		SecLabelID:    SecLabel,
	}
	ep.SetID()

	s.d.OnEndpointJoin = func(receivedEp types.Endpoint) error {
		c.Assert(ep, DeepEquals, receivedEp)
		return nil
	}

	err := s.c.EndpointJoin(ep)
	c.Assert(err, Equals, nil)
}

func (s *DaemonSuite) TestEndpointCreateFail(c *C) {
	ep := types.Endpoint{
		LXCMAC:        HardAddr,
		LXCIP:         EpAddr,
		NodeMAC:       HardAddr,
		NodeIP:        NodeAddr,
		IfName:        "ifname",
		DockerNetwork: "dockernetwork",
		SecLabelID:    SecLabel,
	}
	ep.SetID()

	s.d.OnEndpointJoin = func(receivedEp types.Endpoint) error {
		c.Assert(ep, DeepEquals, receivedEp)
		return errors.New("invalid endpoint")
	}

	err := s.c.EndpointJoin(ep)
	c.Assert(strings.Contains(err.Error(), "invalid endpoint"), Equals, true)
}

func (s *DaemonSuite) TestEndpointLeaveOK(c *C) {
	ep := types.Endpoint{
		LXCMAC:        HardAddr,
		LXCIP:         EpAddr,
		NodeMAC:       HardAddr,
		NodeIP:        NodeAddr,
		IfName:        "ifname",
		DockerNetwork: "dockernetwork",
		SecLabelID:    SecLabel,
	}
	ep.SetID()

	s.d.OnEndpointLeave = func(epIDreceived string) error {
		c.Assert(ep.ID, Equals, epIDreceived)
		return nil
	}

	err := s.c.EndpointLeave(ep.ID)
	c.Assert(err, Equals, nil)
}

func (s *DaemonSuite) TestEndpointLeaveFail(c *C) {
	ep := types.Endpoint{
		LXCMAC:        HardAddr,
		LXCIP:         EpAddr,
		NodeMAC:       HardAddr,
		NodeIP:        NodeAddr,
		IfName:        "ifname",
		DockerNetwork: "dockernetwork",
		SecLabelID:    SecLabel,
	}
	ep.SetID()

	s.d.OnEndpointLeave = func(epIDreceived string) error {
		c.Assert(ep.ID, Equals, epIDreceived)
		return errors.New("invalid endpoint")
	}

	err := s.c.EndpointLeave(ep.ID)
	c.Assert(strings.Contains(err.Error(), "invalid endpoint"), Equals, true)
}

func (s *DaemonSuite) TestEndpointGetOK(c *C) {
	epIDOutside := strconv.FormatUint(uint64(common.EndpointAddr2ID(EpAddr)), 10)
	epWanted := types.Endpoint{
		LXCMAC:        HardAddr,
		LXCIP:         EpAddr,
		NodeMAC:       HardAddr,
		NodeIP:        NodeAddr,
		IfName:        "ifname",
		DockerNetwork: "dockernetwork",
		SecLabelID:    SecLabel,
	}

	s.d.OnEndpointGet = func(epID string) (*types.Endpoint, error) {
		c.Assert(epIDOutside, Equals, epID)
		return &types.Endpoint{
			LXCMAC:        HardAddr,
			LXCIP:         EpAddr,
			NodeMAC:       HardAddr,
			NodeIP:        NodeAddr,
			IfName:        "ifname",
			DockerNetwork: "dockernetwork",
			SecLabelID:    SecLabel,
		}, nil
	}

	ep, err := s.c.EndpointGet(epIDOutside)
	c.Assert(err, IsNil)
	c.Assert(*ep, DeepEquals, epWanted)
}

func (s *DaemonSuite) TestEndpointGetFail(c *C) {
	epIDOutside := strconv.FormatUint(uint64(common.EndpointAddr2ID(EpAddr)), 10)

	s.d.OnEndpointGet = func(epID string) (*types.Endpoint, error) {
		c.Assert(epIDOutside, Equals, epID)
		return nil, errors.New("invalid endpoint")
	}

	_, err := s.c.EndpointGet(epIDOutside)
	c.Logf("err %s", err)
	c.Assert(strings.Contains(err.Error(), "invalid endpoint"), Equals, true)
}
