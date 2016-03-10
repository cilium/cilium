package server

import (
	"errors"
	"net"
	"strings"

	"github.com/noironetworks/cilium-net/common/types"

	. "github.com/noironetworks/cilium-net/Godeps/_workspace/src/gopkg.in/check.v1"
)

var (
	EpAddr          = net.IP{0xbe, 0xef, 0xbe, 0xef, 0xbe, 0xef, 0xbe, 0xef, 0xaa, 0xaa, 0xaa, 0xaa, 0x11, 0x11, 0x11, 0x12}
	NodeAddr        = net.IP{0xbe, 0xef, 0xbe, 0xef, 0xbe, 0xef, 0xbe, 0xef, 0xaa, 0xaa, 0xaa, 0xaa, 0x11, 0x11, 0, 0}
	HardAddr        = net.HardwareAddr{0x01, 0x02, 0x03, 0x04, 0x05, 0x06}
	SecLabel uint32 = 0x200
	EmptyMap        = map[string]*types.Consumer{}
)

func (s *DaemonSuite) TestEndpointCreateOK(c *C) {
	ep := types.Endpoint{
		LxcMAC:        HardAddr,
		LxcIP:         EpAddr,
		NodeMAC:       HardAddr,
		NodeIP:        NodeAddr,
		Ifname:        "ifname",
		DockerNetwork: "dockernetwork",
		SecLabel:      SecLabel,
		Consumers:     EmptyMap,
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
		LxcMAC:        HardAddr,
		LxcIP:         EpAddr,
		NodeMAC:       HardAddr,
		NodeIP:        NodeAddr,
		Ifname:        "ifname",
		DockerNetwork: "dockernetwork",
		SecLabel:      SecLabel,
		Consumers:     EmptyMap,
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
		LxcMAC:        HardAddr,
		LxcIP:         EpAddr,
		NodeMAC:       HardAddr,
		NodeIP:        NodeAddr,
		Ifname:        "ifname",
		DockerNetwork: "dockernetwork",
		SecLabel:      SecLabel,
		Consumers:     EmptyMap,
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
		LxcMAC:        HardAddr,
		LxcIP:         EpAddr,
		NodeMAC:       HardAddr,
		NodeIP:        NodeAddr,
		Ifname:        "ifname",
		DockerNetwork: "dockernetwork",
		SecLabel:      SecLabel,
		Consumers:     EmptyMap,
	}
	ep.SetID()

	s.d.OnEndpointLeave = func(epIDreceived string) error {
		c.Assert(ep.ID, Equals, epIDreceived)
		return errors.New("invalid endpoint")
	}

	err := s.c.EndpointLeave(ep.ID)
	c.Assert(strings.Contains(err.Error(), "invalid endpoint"), Equals, true)
}
