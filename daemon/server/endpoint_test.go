package server

import (
	"errors"
	"net"
	"strconv"
	"strings"
	"time"

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
		Containers: map[string]time.Time{
			"cc08ff400e355f736dce1c291a6a4007ab9f2d56d42e1f3630ba87b861d45307": time.Now(),
		},
		ID: 0x100,
	}
)

func (s *DaemonSuite) TestEndpointJoinOK(c *C) {
	ep := types.Endpoint{
		LXCMAC:          HardAddr,
		LXCIP:           EpAddr,
		NodeMAC:         HardAddr,
		NodeIP:          NodeAddr,
		IfName:          "ifname",
		DockerNetworkID: "dockernetwork",
		SecLabel:        SecLabel,
	}
	ep.SetID()

	s.d.OnEndpointJoin = func(receivedEp types.Endpoint) error {
		c.Assert(ep, DeepEquals, receivedEp)
		return nil
	}

	err := s.c.EndpointJoin(ep)
	c.Assert(err, Equals, nil)
}

func (s *DaemonSuite) TestEndpointJoinFail(c *C) {
	ep := types.Endpoint{
		LXCMAC:          HardAddr,
		LXCIP:           EpAddr,
		NodeMAC:         HardAddr,
		NodeIP:          NodeAddr,
		IfName:          "ifname",
		DockerNetworkID: "dockernetwork",
		SecLabel:        SecLabel,
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
		LXCMAC:          HardAddr,
		LXCIP:           EpAddr,
		NodeMAC:         HardAddr,
		NodeIP:          NodeAddr,
		IfName:          "ifname",
		DockerNetworkID: "dockernetwork",
		SecLabel:        SecLabel,
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
		LXCMAC:          HardAddr,
		LXCIP:           EpAddr,
		NodeMAC:         HardAddr,
		NodeIP:          NodeAddr,
		IfName:          "ifname",
		DockerNetworkID: "dockernetwork",
		SecLabel:        SecLabel,
	}
	ep.SetID()

	s.d.OnEndpointLeave = func(epIDreceived string) error {
		c.Assert(ep.ID, Equals, epIDreceived)
		return errors.New("invalid endpoint")
	}

	err := s.c.EndpointLeave(ep.ID)
	c.Assert(strings.Contains(err.Error(), "invalid endpoint"), Equals, true)
}

func (s *DaemonSuite) EndpointLeaveByDockerEPIDOK(c *C) {
	ep := types.Endpoint{
		LXCMAC:           HardAddr,
		LXCIP:            EpAddr,
		NodeMAC:          HardAddr,
		NodeIP:           NodeAddr,
		IfName:           "ifname",
		DockerNetworkID:  "dockernetwork",
		DockerEndpointID: "123abc",
		SecLabel:         SecLabel,
	}
	ep.SetID()

	s.d.OnEndpointLeaveByDockerEPID = func(dockerEPIDreceived string) error {
		c.Assert(ep.DockerEndpointID, Equals, dockerEPIDreceived)
		return nil
	}

	err := s.c.EndpointLeaveByDockerEPID(ep.DockerEndpointID)
	c.Assert(err, Equals, nil)
}

func (s *DaemonSuite) EndpointLeaveByDockerEPIDFail(c *C) {
	ep := types.Endpoint{
		LXCMAC:           HardAddr,
		LXCIP:            EpAddr,
		NodeMAC:          HardAddr,
		NodeIP:           NodeAddr,
		IfName:           "ifname",
		DockerNetworkID:  "dockernetwork",
		DockerEndpointID: "123abc",
		SecLabel:         SecLabel,
	}
	ep.SetID()

	s.d.OnEndpointLeaveByDockerEPID = func(dockerEPIDreceived string) error {
		c.Assert(ep.DockerEndpointID, Equals, dockerEPIDreceived)
		return errors.New("invalid endpoint")
	}

	err := s.c.EndpointLeaveByDockerEPID(ep.DockerEndpointID)
	c.Assert(strings.Contains(err.Error(), "invalid endpoint"), Equals, true)
}

func (s *DaemonSuite) TestEndpointGetOK(c *C) {
	epIDOutside := strconv.FormatUint(uint64(common.EndpointAddr2ID(EpAddr)), 10)
	epWanted := types.Endpoint{
		LXCMAC:          HardAddr,
		LXCIP:           EpAddr,
		NodeMAC:         HardAddr,
		NodeIP:          NodeAddr,
		IfName:          "ifname",
		DockerNetworkID: "dockernetwork",
		SecLabel:        SecLabel,
	}

	s.d.OnEndpointGet = func(epID string) (*types.Endpoint, error) {
		c.Assert(epIDOutside, Equals, epID)
		return &types.Endpoint{
			LXCMAC:          HardAddr,
			LXCIP:           EpAddr,
			NodeMAC:         HardAddr,
			NodeIP:          NodeAddr,
			IfName:          "ifname",
			DockerNetworkID: "dockernetwork",
			SecLabel:        SecLabel,
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

func (s *DaemonSuite) TestEndpointGetByDockerEPIDOK(c *C) {
	epWanted := types.Endpoint{
		LXCMAC:           HardAddr,
		LXCIP:            EpAddr,
		NodeMAC:          HardAddr,
		NodeIP:           NodeAddr,
		IfName:           "ifname",
		DockerNetworkID:  "dockernetwork",
		DockerEndpointID: "123abc",
		SecLabel:         SecLabel,
	}

	s.d.OnEndpointGetByDockerEPID = func(dockerEPID string) (*types.Endpoint, error) {
		c.Assert(dockerEPID, Equals, "123abc")
		return &types.Endpoint{
			LXCMAC:           HardAddr,
			LXCIP:            EpAddr,
			NodeMAC:          HardAddr,
			NodeIP:           NodeAddr,
			IfName:           "ifname",
			DockerNetworkID:  "dockernetwork",
			DockerEndpointID: "123abc",
			SecLabel:         SecLabel,
		}, nil
	}

	ep, err := s.c.EndpointGetByDockerEPID(epWanted.DockerEndpointID)
	c.Assert(err, IsNil)
	c.Assert(*ep, DeepEquals, epWanted)
}

func (s *DaemonSuite) TestEndpointGetByDockerEPIDFail(c *C) {
	dockerEPID := "123abc"

	s.d.OnEndpointGetByDockerEPID = func(dockerEPID string) (*types.Endpoint, error) {
		c.Assert(dockerEPID, Equals, dockerEPID)
		return nil, errors.New("invalid endpoint")
	}

	_, err := s.c.EndpointGetByDockerEPID(dockerEPID)
	c.Logf("err %s", err)
	c.Assert(strings.Contains(err.Error(), "invalid endpoint"), Equals, true)
}

func (s *DaemonSuite) TestEndpointsGetOK(c *C) {
	epsWanted := []types.Endpoint{
		types.Endpoint{
			LXCMAC:          HardAddr,
			LXCIP:           EpAddr,
			NodeMAC:         HardAddr,
			NodeIP:          NodeAddr,
			IfName:          "ifname",
			DockerNetworkID: "dockernetwork",
			SecLabel:        SecLabel,
		},
		types.Endpoint{
			LXCMAC:          HardAddr,
			LXCIP:           EpAddr,
			NodeMAC:         HardAddr,
			NodeIP:          NodeAddr,
			IfName:          "ifname1",
			DockerNetworkID: "dockernetwork1",
			SecLabel:        SecLabel,
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

func (s *DaemonSuite) TestEndpointSaveOK(c *C) {
	ep := types.Endpoint{
		LXCMAC:          HardAddr,
		LXCIP:           EpAddr,
		NodeMAC:         HardAddr,
		NodeIP:          NodeAddr,
		IfName:          "ifname",
		DockerNetworkID: "dockernetwork",
		SecLabel:        SecLabel,
	}
	ep.SetID()

	s.d.OnEndpointSave = func(receivedEp types.Endpoint) error {
		c.Assert(ep, DeepEquals, receivedEp)
		return nil
	}

	err := s.c.EndpointSave(ep)
	c.Assert(err, Equals, nil)
}

func (s *DaemonSuite) TestEndpointSaveFail(c *C) {
	ep := types.Endpoint{
		LXCMAC:          HardAddr,
		LXCIP:           EpAddr,
		NodeMAC:         HardAddr,
		NodeIP:          NodeAddr,
		IfName:          "ifname",
		DockerNetworkID: "dockernetwork",
		SecLabel:        SecLabel,
	}
	ep.SetID()

	s.d.OnEndpointSave = func(receivedEp types.Endpoint) error {
		c.Assert(ep, DeepEquals, receivedEp)
		return errors.New("invalid endpoint")
	}

	err := s.c.EndpointSave(ep)
	c.Assert(strings.Contains(err.Error(), "invalid endpoint"), Equals, true)
}

func (s *DaemonSuite) TestEndpointLabelsGetOK(c *C) {
	ep := types.Endpoint{
		LXCMAC:          HardAddr,
		LXCIP:           EpAddr,
		NodeMAC:         HardAddr,
		NodeIP:          NodeAddr,
		IfName:          "ifname",
		DockerNetworkID: "dockernetwork",
		SecLabel:        SecLabel,
	}
	ep.SetID()

	epLbls := types.Labels{
		"foo": types.NewLabel("foo", "bar", "cilium"),
	}
	ciliumLbls := types.Labels{
		"bar": types.NewLabel("bar", "foo", "cilium"),
	}
	wantedLbls := types.OpLabels{
		AllLabels:      ciliumLbls,
		EndpointLabels: epLbls,
	}

	s.d.OnEndpointLabelsGet = func(epID string) (*types.OpLabels, error) {
		c.Assert(ep.ID, DeepEquals, epID)
		return &wantedLbls, nil
	}

	lbls, err := s.c.EndpointLabelsGet(ep.ID)
	c.Assert(err, IsNil)
	c.Assert(wantedLbls, DeepEquals, *lbls)
}

func (s *DaemonSuite) TestEndpointLabelsGetFail(c *C) {
	ep := types.Endpoint{
		LXCMAC:          HardAddr,
		LXCIP:           EpAddr,
		NodeMAC:         HardAddr,
		NodeIP:          NodeAddr,
		IfName:          "ifname",
		DockerNetworkID: "dockernetwork",
		SecLabel:        SecLabel,
	}
	ep.SetID()

	s.d.OnEndpointLabelsGet = func(epID string) (*types.OpLabels, error) {
		c.Assert(ep.ID, DeepEquals, epID)
		return nil, errors.New("invalid endpoint")
	}

	lbls, err := s.c.EndpointLabelsGet(ep.ID)
	c.Assert(strings.Contains(err.Error(), "invalid endpoint"), Equals, true)
	c.Assert(lbls, IsNil)
}

func (s *DaemonSuite) TestEndpointLabelsAddOK(c *C) {
	ep := types.Endpoint{
		LXCMAC:          HardAddr,
		LXCIP:           EpAddr,
		NodeMAC:         HardAddr,
		NodeIP:          NodeAddr,
		IfName:          "ifname",
		DockerNetworkID: "dockernetwork",
		SecLabel:        SecLabel,
	}
	ep.SetID()

	wantedLabels := types.Labels{
		"foo": types.NewLabel("foo", "bar", "cilium"),
	}

	s.d.OnEndpointLabelsUpdate = func(epID string, op types.LabelOP, lbls types.Labels) error {
		c.Assert(ep.ID, DeepEquals, epID)
		c.Assert(op, Equals, types.AddLabelsOp)
		c.Assert(wantedLabels, DeepEquals, lbls)
		return nil
	}

	err := s.c.EndpointLabelsUpdate(ep.ID, types.AddLabelsOp, wantedLabels)
	c.Assert(err, IsNil)
}

func (s *DaemonSuite) TestEndpointLabelsAddFail(c *C) {
	ep := types.Endpoint{
		LXCMAC:          HardAddr,
		LXCIP:           EpAddr,
		NodeMAC:         HardAddr,
		NodeIP:          NodeAddr,
		IfName:          "ifname",
		DockerNetworkID: "dockernetwork",
		SecLabel:        SecLabel,
	}
	ep.SetID()

	wantedLabels := types.Labels{
		"foo": types.NewLabel("foo", "bar", "cilium"),
	}

	s.d.OnEndpointLabelsUpdate = func(epID string, op types.LabelOP, lbls types.Labels) error {
		c.Assert(ep.ID, DeepEquals, epID)
		c.Assert(op, Equals, types.AddLabelsOp)
		c.Assert(wantedLabels, DeepEquals, lbls)
		return errors.New("invalid endpoint")
	}

	err := s.c.EndpointLabelsUpdate(ep.ID, types.AddLabelsOp, wantedLabels)
	c.Assert(strings.Contains(err.Error(), "invalid endpoint"), Equals, true)
}
