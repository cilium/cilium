//
// Copyright 2016 Authors of Cilium
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
//
package server

import (
	"errors"
	"net"
	"strings"
	"time"

	"github.com/cilium/cilium/common/addressing"
	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/mac"
	"github.com/cilium/cilium/pkg/option"

	. "gopkg.in/check.v1"
)

var (
	IPv6Addr, _ = addressing.NewCiliumIPv6("beef:beef:beef:beef:aaaa:aaaa:1111:1112")
	IPv4Addr, _ = addressing.NewCiliumIPv4("10.11.12.13")
	NodeAddr    = net.IP{0xbe, 0xef, 0xbe, 0xef, 0xbe, 0xef, 0xbe, 0xef, 0xaa, 0xaa, 0xaa, 0xaa, 0x11, 0x11, 0, 0}
	HardAddr    = mac.MAC{0x01, 0x02, 0x03, 0x04, 0x05, 0x06}
	SecLabel    = &labels.SecCtxLabel{
		Labels: labels.Labels{
			"foo": labels.NewLabel("foo", "", ""),
		},
		Containers: map[string]time.Time{
			"cc08ff400e355f736dce1c291a6a4007ab9f2d56d42e1f3630ba87b861d45307": time.Now(),
		},
		ID: 0x100,
	}
)

func (s *DaemonSuite) TestEndpointJoinOK(c *C) {
	ep := endpoint.Endpoint{
		LXCMAC:          HardAddr,
		IPv6:            IPv6Addr,
		IPv4:            IPv4Addr,
		NodeMAC:         HardAddr,
		NodeIP:          NodeAddr,
		IfName:          "ifname",
		DockerNetworkID: "dockernetwork",
		SecLabel:        SecLabel,
	}
	ep.SetID()

	s.d.OnEndpointJoin = func(receivedEp endpoint.Endpoint) error {
		c.Assert(ep, DeepEquals, receivedEp)
		return nil
	}

	err := s.c.EndpointJoin(ep)
	c.Assert(err, Equals, nil)
}

func (s *DaemonSuite) TestEndpointJoinFail(c *C) {
	ep := endpoint.Endpoint{
		LXCMAC:          HardAddr,
		IPv6:            IPv6Addr,
		IPv4:            IPv4Addr,
		NodeMAC:         HardAddr,
		NodeIP:          NodeAddr,
		IfName:          "ifname",
		DockerNetworkID: "dockernetwork",
		SecLabel:        SecLabel,
	}
	ep.SetID()

	s.d.OnEndpointJoin = func(receivedEp endpoint.Endpoint) error {
		c.Assert(ep, DeepEquals, receivedEp)
		return errors.New("invalid endpoint")
	}

	err := s.c.EndpointJoin(ep)
	c.Assert(strings.Contains(err.Error(), "invalid endpoint"), Equals, true)
}

func (s *DaemonSuite) TestEndpointLeaveOK(c *C) {
	ep := endpoint.Endpoint{
		LXCMAC:          HardAddr,
		IPv6:            IPv6Addr,
		IPv4:            IPv4Addr,
		NodeMAC:         HardAddr,
		NodeIP:          NodeAddr,
		IfName:          "ifname",
		DockerNetworkID: "dockernetwork",
		SecLabel:        SecLabel,
	}
	ep.SetID()

	s.d.OnEndpointLeave = func(epID uint16) error {
		c.Assert(ep.ID, Equals, epID)
		return nil
	}

	err := s.c.EndpointLeave(ep.ID)
	c.Assert(err, Equals, nil)
}

func (s *DaemonSuite) TestEndpointLeaveFail(c *C) {
	ep := endpoint.Endpoint{
		LXCMAC:          HardAddr,
		IPv6:            IPv6Addr,
		IPv4:            IPv4Addr,
		NodeMAC:         HardAddr,
		NodeIP:          NodeAddr,
		IfName:          "ifname",
		DockerNetworkID: "dockernetwork",
		SecLabel:        SecLabel,
	}
	ep.SetID()

	s.d.OnEndpointLeave = func(epID uint16) error {
		c.Assert(ep.ID, Equals, epID)
		return errors.New("invalid endpoint")
	}

	err := s.c.EndpointLeave(ep.ID)
	c.Assert(strings.Contains(err.Error(), "invalid endpoint"), Equals, true)
}

func (s *DaemonSuite) EndpointLeaveByDockerEPIDOK(c *C) {
	ep := endpoint.Endpoint{
		LXCMAC:           HardAddr,
		IPv6:             IPv6Addr,
		IPv4:             IPv4Addr,
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
	ep := endpoint.Endpoint{
		LXCMAC:           HardAddr,
		IPv6:             IPv6Addr,
		IPv4:             IPv4Addr,
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
	epIDOutside := IPv6Addr.EndpointID()
	epWanted := endpoint.Endpoint{
		LXCMAC:          HardAddr,
		IPv6:            IPv6Addr,
		IPv4:            IPv4Addr,
		NodeMAC:         HardAddr,
		NodeIP:          NodeAddr,
		IfName:          "ifname",
		DockerNetworkID: "dockernetwork",
		SecLabel:        SecLabel,
	}

	s.d.OnEndpointGet = func(epID uint16) (*endpoint.Endpoint, error) {
		c.Assert(epIDOutside, Equals, epID)
		return &endpoint.Endpoint{
			LXCMAC:          HardAddr,
			IPv6:            IPv6Addr,
			IPv4:            IPv4Addr,
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
	epIDOutside := IPv6Addr.EndpointID()

	s.d.OnEndpointGet = func(epID uint16) (*endpoint.Endpoint, error) {
		c.Assert(epIDOutside, Equals, epID)
		return nil, errors.New("invalid endpoint")
	}

	_, err := s.c.EndpointGet(epIDOutside)
	c.Logf("err %s", err)
	c.Assert(strings.Contains(err.Error(), "invalid endpoint"), Equals, true)
}

func (s *DaemonSuite) TestEndpointGetByDockerEPIDOK(c *C) {
	epWanted := endpoint.Endpoint{
		LXCMAC:           HardAddr,
		IPv6:             IPv6Addr,
		IPv4:             IPv4Addr,
		NodeMAC:          HardAddr,
		NodeIP:           NodeAddr,
		IfName:           "ifname",
		DockerNetworkID:  "dockernetwork",
		DockerEndpointID: "123abc",
		SecLabel:         SecLabel,
	}

	s.d.OnEndpointGetByDockerEPID = func(dockerEPID string) (*endpoint.Endpoint, error) {
		c.Assert(dockerEPID, Equals, "123abc")
		return &endpoint.Endpoint{
			LXCMAC:           HardAddr,
			IPv6:             IPv6Addr,
			IPv4:             IPv4Addr,
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

	s.d.OnEndpointGetByDockerEPID = func(dockerEPID string) (*endpoint.Endpoint, error) {
		c.Assert(dockerEPID, Equals, dockerEPID)
		return nil, errors.New("invalid endpoint")
	}

	_, err := s.c.EndpointGetByDockerEPID(dockerEPID)
	c.Logf("err %s", err)
	c.Assert(strings.Contains(err.Error(), "invalid endpoint"), Equals, true)
}

func (s *DaemonSuite) TestEndpointGetByDockerIDOK(c *C) {
	epWanted := endpoint.Endpoint{
		LXCMAC:          HardAddr,
		IPv6:            IPv6Addr,
		IPv4:            IPv4Addr,
		NodeMAC:         HardAddr,
		NodeIP:          NodeAddr,
		IfName:          "ifname",
		DockerNetworkID: "dockernetwork",
		DockerID:        "123abc",
		SecLabel:        SecLabel,
	}

	s.d.OnEndpointGetByDockerID = func(dockerID string) (*endpoint.Endpoint, error) {
		c.Assert(dockerID, Equals, "123abc")
		return &endpoint.Endpoint{
			LXCMAC:          HardAddr,
			IPv6:            IPv6Addr,
			IPv4:            IPv4Addr,
			NodeMAC:         HardAddr,
			NodeIP:          NodeAddr,
			IfName:          "ifname",
			DockerNetworkID: "dockernetwork",
			DockerID:        "123abc",
			SecLabel:        SecLabel,
		}, nil
	}

	ep, err := s.c.EndpointGetByDockerID(epWanted.DockerID)
	c.Assert(err, IsNil)
	c.Assert(*ep, DeepEquals, epWanted)
}

func (s *DaemonSuite) TestEndpointGetByDockerIDFail(c *C) {
	dockerID := "123abc"

	s.d.OnEndpointGetByDockerID = func(dockerID string) (*endpoint.Endpoint, error) {
		c.Assert(dockerID, Equals, dockerID)
		return nil, errors.New("invalid endpoint")
	}

	_, err := s.c.EndpointGetByDockerID(dockerID)
	c.Logf("err %s", err)
	c.Assert(strings.Contains(err.Error(), "invalid endpoint"), Equals, true)
}

func (s *DaemonSuite) TestEndpointsGetOK(c *C) {
	epsWanted := []endpoint.Endpoint{
		{
			LXCMAC:          HardAddr,
			IPv6:            IPv6Addr,
			IPv4:            IPv4Addr,
			NodeMAC:         HardAddr,
			NodeIP:          NodeAddr,
			IfName:          "ifname",
			DockerNetworkID: "dockernetwork",
			SecLabel:        SecLabel,
		},
		{
			LXCMAC:          HardAddr,
			IPv6:            IPv6Addr,
			IPv4:            IPv4Addr,
			NodeMAC:         HardAddr,
			NodeIP:          NodeAddr,
			IfName:          "ifname1",
			DockerNetworkID: "dockernetwork1",
			SecLabel:        SecLabel,
		},
	}

	s.d.OnEndpointsGet = func() ([]endpoint.Endpoint, error) {
		return epsWanted, nil
	}

	eps, err := s.c.EndpointsGet()
	c.Assert(err, IsNil)
	c.Assert(eps, DeepEquals, epsWanted)
}

func (s *DaemonSuite) TestEndpointsGetFail(c *C) {
	s.d.OnEndpointsGet = func() ([]endpoint.Endpoint, error) {
		return nil, errors.New("invalid endpoint")
	}

	_, err := s.c.EndpointsGet()
	c.Assert(strings.Contains(err.Error(), "invalid endpoint"), Equals, true)
}

func (s *DaemonSuite) TestEndpointUpdateOK(c *C) {
	optsWanted := option.OptionMap{"FOO": true}

	s.d.OnEndpointUpdate = func(epID uint16, opts option.OptionMap) error {
		c.Assert(epID, DeepEquals, uint16(4307))
		c.Assert(opts, DeepEquals, optsWanted)
		return nil
	}

	err := s.c.EndpointUpdate(4307, optsWanted)
	c.Assert(err, IsNil)

	s.d.OnEndpointUpdate = func(epID uint16, opts option.OptionMap) error {
		c.Assert(epID, DeepEquals, uint16(4307))
		c.Assert(opts, IsNil)
		return nil
	}
	err = s.c.EndpointUpdate(4307, nil)
	c.Assert(err, IsNil)
}

func (s *DaemonSuite) TestEndpointUpdateFail(c *C) {
	optsWanted := option.OptionMap{"FOO": true}

	s.d.OnEndpointUpdate = func(epID uint16, opts option.OptionMap) error {
		c.Assert(epID, DeepEquals, uint16(4307))
		c.Assert(opts, DeepEquals, optsWanted)
		return errors.New("invalid endpoint")
	}

	err := s.c.EndpointUpdate(4307, optsWanted)
	c.Assert(strings.Contains(err.Error(), "invalid endpoint"), Equals, true)
}

func (s *DaemonSuite) TestEndpointSaveOK(c *C) {
	ep := endpoint.Endpoint{
		LXCMAC:          HardAddr,
		IPv6:            IPv6Addr,
		IPv4:            IPv4Addr,
		NodeMAC:         HardAddr,
		NodeIP:          NodeAddr,
		IfName:          "ifname",
		DockerNetworkID: "dockernetwork",
		SecLabel:        SecLabel,
	}
	ep.SetID()

	s.d.OnEndpointSave = func(receivedEp endpoint.Endpoint) error {
		c.Assert(ep, DeepEquals, receivedEp)
		return nil
	}

	err := s.c.EndpointSave(ep)
	c.Assert(err, Equals, nil)
}

func (s *DaemonSuite) TestEndpointSaveFail(c *C) {
	ep := endpoint.Endpoint{
		LXCMAC:          HardAddr,
		IPv6:            IPv6Addr,
		IPv4:            IPv4Addr,
		NodeMAC:         HardAddr,
		NodeIP:          NodeAddr,
		IfName:          "ifname",
		DockerNetworkID: "dockernetwork",
		SecLabel:        SecLabel,
	}
	ep.SetID()

	s.d.OnEndpointSave = func(receivedEp endpoint.Endpoint) error {
		c.Assert(ep, DeepEquals, receivedEp)
		return errors.New("invalid endpoint")
	}

	err := s.c.EndpointSave(ep)
	c.Assert(strings.Contains(err.Error(), "invalid endpoint"), Equals, true)
}

func (s *DaemonSuite) TestEndpointLabelsGetOK(c *C) {
	ep := endpoint.Endpoint{
		LXCMAC:          HardAddr,
		IPv6:            IPv6Addr,
		IPv4:            IPv4Addr,
		NodeMAC:         HardAddr,
		NodeIP:          NodeAddr,
		IfName:          "ifname",
		DockerNetworkID: "dockernetwork",
		SecLabel:        SecLabel,
	}
	ep.SetID()

	epLbls := labels.Labels{
		"foo": labels.NewLabel("foo", "bar", "cilium"),
	}
	ciliumLbls := labels.Labels{
		"bar": labels.NewLabel("bar", "foo", "cilium"),
	}
	wantedLbls := labels.OpLabels{
		AllLabels:      ciliumLbls,
		EndpointLabels: epLbls,
	}

	s.d.OnEndpointLabelsGet = func(epID uint16) (*labels.OpLabels, error) {
		c.Assert(ep.ID, DeepEquals, epID)
		return &wantedLbls, nil
	}

	lbls, err := s.c.EndpointLabelsGet(ep.ID)
	c.Assert(err, IsNil)
	c.Assert(wantedLbls, DeepEquals, *lbls)
}

func (s *DaemonSuite) TestEndpointLabelsGetFail(c *C) {
	ep := endpoint.Endpoint{
		LXCMAC:          HardAddr,
		IPv6:            IPv6Addr,
		IPv4:            IPv4Addr,
		NodeMAC:         HardAddr,
		NodeIP:          NodeAddr,
		IfName:          "ifname",
		DockerNetworkID: "dockernetwork",
		SecLabel:        SecLabel,
	}
	ep.SetID()

	s.d.OnEndpointLabelsGet = func(epID uint16) (*labels.OpLabels, error) {
		c.Assert(ep.ID, DeepEquals, epID)
		return nil, errors.New("invalid endpoint")
	}

	lbls, err := s.c.EndpointLabelsGet(ep.ID)
	c.Assert(strings.Contains(err.Error(), "invalid endpoint"), Equals, true)
	c.Assert(lbls, IsNil)
}

func (s *DaemonSuite) TestEndpointLabelsAddOK(c *C) {
	ep := endpoint.Endpoint{
		LXCMAC:          HardAddr,
		IPv6:            IPv6Addr,
		IPv4:            IPv4Addr,
		NodeMAC:         HardAddr,
		NodeIP:          NodeAddr,
		IfName:          "ifname",
		DockerNetworkID: "dockernetwork",
		SecLabel:        SecLabel,
	}
	ep.SetID()

	wantedLabels := labels.LabelOp{
		labels.AddLabelsOp: labels.Labels{
			"foo": labels.NewLabel("foo", "bar", "cilium"),
		},
	}

	s.d.OnEndpointLabelsUpdate = func(epID uint16, lbls labels.LabelOp) error {
		c.Assert(ep.ID, DeepEquals, epID)
		c.Assert(wantedLabels, DeepEquals, lbls)
		return nil
	}

	err := s.c.EndpointLabelsUpdate(ep.ID, wantedLabels)
	c.Assert(err, IsNil)
}

func (s *DaemonSuite) TestEndpointLabelsAddFail(c *C) {
	ep := endpoint.Endpoint{
		LXCMAC:          HardAddr,
		IPv6:            IPv6Addr,
		IPv4:            IPv4Addr,
		NodeMAC:         HardAddr,
		NodeIP:          NodeAddr,
		IfName:          "ifname",
		DockerNetworkID: "dockernetwork",
		SecLabel:        SecLabel,
	}
	ep.SetID()

	wantedLabels := labels.LabelOp{
		labels.AddLabelsOp: labels.Labels{
			"foo": labels.NewLabel("foo", "bar", "cilium"),
		},
	}

	s.d.OnEndpointLabelsUpdate = func(epID uint16, labelOp labels.LabelOp) error {
		c.Assert(ep.ID, DeepEquals, epID)
		c.Assert(labelOp, DeepEquals, wantedLabels)
		return errors.New("invalid endpoint")
	}

	err := s.c.EndpointLabelsUpdate(ep.ID, wantedLabels)
	c.Assert(strings.Contains(err.Error(), "invalid endpoint"), Equals, true)
}
