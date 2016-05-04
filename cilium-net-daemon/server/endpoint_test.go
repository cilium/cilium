package server

import (
	"errors"
	"net"
	"strconv"
	"strings"

	"github.com/noironetworks/cilium-net/common"
	"github.com/noironetworks/cilium-net/common/types"

	. "gopkg.in/check.v1"
)

var (
	EpAddr   = net.IP{0xbe, 0xef, 0xbe, 0xef, 0xbe, 0xef, 0xbe, 0xef, 0xaa, 0xaa, 0xaa, 0xaa, 0x11, 0x11, 0x11, 0x12}
	NodeAddr = net.IP{0xbe, 0xef, 0xbe, 0xef, 0xbe, 0xef, 0xbe, 0xef, 0xaa, 0xaa, 0xaa, 0xaa, 0x11, 0x11, 0, 0}
	HardAddr = types.MAC{0x01, 0x02, 0x03, 0x04, 0x05, 0x06}
	SecLabel = &types.SecCtxLabel{
		Labels: types.Labels{
			"foo": types.NewLabel("foo", "", ""),
		},
		RefCount: 1,
		ID:       0x100,
	}
)

func (s *DaemonSuite) TestEndpointCreateOK(c *C) {
	ep := types.Endpoint{
		LXCMAC:        HardAddr,
		LXCIP:         EpAddr,
		NodeMAC:       HardAddr,
		NodeIP:        NodeAddr,
		IfName:        "ifname",
		DockerNetwork: "dockernetwork",
		SecLabel:      SecLabel,
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
		SecLabel:      SecLabel,
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
		SecLabel:      SecLabel,
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
		SecLabel:      SecLabel,
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
		SecLabel:      SecLabel,
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
			SecLabel:      SecLabel,
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

func (s *DaemonSuite) TestEndpointsGetOK(c *C) {
	epsWanted := []types.Endpoint{
		types.Endpoint{
			LXCMAC:        HardAddr,
			LXCIP:         EpAddr,
			NodeMAC:       HardAddr,
			NodeIP:        NodeAddr,
			IfName:        "ifname",
			DockerNetwork: "dockernetwork",
			SecLabel:      SecLabel,
		},
		types.Endpoint{
			LXCMAC:        HardAddr,
			LXCIP:         EpAddr,
			NodeMAC:       HardAddr,
			NodeIP:        NodeAddr,
			IfName:        "ifname1",
			DockerNetwork: "dockernetwork1",
			SecLabel:      SecLabel,
		},
	}

	s.d.OnEndpointsGet = func() ([]types.Endpoint, error) {
		return epsWanted, nil
	}

	eps, err := s.c.EndpointsGet()
	c.Assert(err, IsNil)
	c.Assert(eps, DeepEquals, epsWanted)
}

func (s *DaemonSuite) TestEndpointsGetFail(c *C) {
	s.d.OnEndpointsGet = func() ([]types.Endpoint, error) {
		return nil, errors.New("invalid endpoint")
	}

	_, err := s.c.EndpointsGet()
	c.Assert(strings.Contains(err.Error(), "invalid endpoint"), Equals, true)
}

func (s *DaemonSuite) TestEndpointUpdateOK(c *C) {
	optsWanted := types.EPOpts{"FOO": true}

	s.d.OnEndpointUpdate = func(epID string, opts types.EPOpts) error {
		c.Assert(epID, DeepEquals, "4307")
		c.Assert(opts, DeepEquals, optsWanted)
		return nil
	}

	err := s.c.EndpointUpdate("4307", optsWanted)
	c.Assert(err, IsNil)

	s.d.OnEndpointUpdate = func(epID string, opts types.EPOpts) error {
		c.Assert(epID, DeepEquals, "4307")
		c.Assert(opts, IsNil)
		return nil
	}
	err = s.c.EndpointUpdate("4307", nil)
	c.Assert(err, IsNil)
}

func (s *DaemonSuite) TestEndpointUpdateFail(c *C) {
	optsWanted := types.EPOpts{"FOO": true}

	s.d.OnEndpointUpdate = func(epID string, opts types.EPOpts) error {
		c.Assert(epID, DeepEquals, "4307")
		c.Assert(opts, DeepEquals, optsWanted)
		return errors.New("invalid endpoint")
	}

	err := s.c.EndpointUpdate("4307", optsWanted)
	c.Assert(strings.Contains(err.Error(), "invalid endpoint"), Equals, true)
}
