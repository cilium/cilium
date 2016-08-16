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

	"github.com/cilium/cilium/common/addressing"
	"github.com/cilium/cilium/common/ipam"

	lnTypes "github.com/docker/libnetwork/types"
	. "gopkg.in/check.v1"
)

func (s *DaemonSuite) TestAllocateIPOK(c *C) {
	ipamConfig := ipam.IPAMRep{
		IP6: &ipam.IPConfig{
			Gateway: NodeAddr,
			IP:      net.IPNet{IP: IPv6Addr.IP(), Mask: addressing.NodeIPv6Mask},
			Routes: []ipam.Route{
				ipam.Route{
					Destination: net.IPNet{IP: net.IPv6zero, Mask: net.CIDRMask(0, 128)},
					NextHop:     nil,
					Type:        lnTypes.CONNECTED,
				},
			},
		},
	}

	ipamReq := ipam.IPAMReq{ContainerID: "11b3354cca51cf41ef05f338ec6c1016d03f9496ff701b6060b649248ae07523"}

	s.d.OnAllocateIP = func(ipamType ipam.IPAMType, opts ipam.IPAMReq) (*ipam.IPAMRep, error) {
		c.Assert(ipamType, Equals, ipam.CNIIPAMType)
		c.Assert(opts, Equals, ipamReq)
		return &ipamConfig, nil
	}

	ipamConfigReceived, err := s.c.AllocateIP(ipam.CNIIPAMType, ipamReq)
	c.Assert(err, Equals, nil)
	c.Assert(ipamConfig, DeepEquals, *ipamConfigReceived)

	s.d.OnAllocateIP = func(ipamType ipam.IPAMType, opts ipam.IPAMReq) (*ipam.IPAMRep, error) {
		c.Assert(ipamType, Equals, ipam.LibnetworkIPAMType)
		c.Assert(opts, Equals, ipamReq)
		return nil, nil
	}

	ipamConfigReceived, err = s.c.AllocateIP(ipam.LibnetworkIPAMType, ipamReq)
	c.Assert(err, Equals, nil)
	c.Assert(ipamConfigReceived, IsNil)
}

func (s *DaemonSuite) TestAllocateIPFail(c *C) {
	ipamReq := ipam.IPAMReq{ContainerID: "11b3354cca51cf41ef05f338ec6c1016d03f9496ff701b6060b649248ae07523"}

	s.d.OnAllocateIP = func(ipamType ipam.IPAMType, opts ipam.IPAMReq) (*ipam.IPAMRep, error) {
		c.Assert(ipamType, Equals, ipam.CNIIPAMType)
		c.Assert(opts, Equals, ipamReq)
		return nil, errors.New("IP allocator full")
	}

	_, err := s.c.AllocateIP(ipam.CNIIPAMType, ipamReq)
	c.Assert(strings.Contains(err.Error(), "IP allocator full"), Equals, true)
}

func (s *DaemonSuite) TestReleaseIPOK(c *C) {
	ipamReq := ipam.IPAMReq{ContainerID: "11b3354cca51cf41ef05f338ec6c1016d03f9496ff701b6060b649248ae07523"}

	s.d.OnReleaseIP = func(ipamType ipam.IPAMType, opts ipam.IPAMReq) error {
		c.Assert(ipamType, Equals, ipam.CNIIPAMType)
		c.Assert(opts, Equals, ipamReq)
		return nil
	}

	err := s.c.ReleaseIP(ipam.CNIIPAMType, ipamReq)
	c.Assert(err, Equals, nil)
}

func (s *DaemonSuite) TestReleaseIPFail(c *C) {
	ipamReq := ipam.IPAMReq{ContainerID: "11b3354cca51cf41ef05f338ec6c1016d03f9496ff701b6060b649248ae07523"}

	s.d.OnReleaseIP = func(ipamType ipam.IPAMType, opts ipam.IPAMReq) error {
		c.Assert(ipamType, Equals, ipam.CNIIPAMType)
		c.Assert(opts, Equals, ipamReq)
		return errors.New("IP allocator didn't found container")
	}

	err := s.c.ReleaseIP(ipam.CNIIPAMType, ipamReq)
	c.Assert(strings.Contains(err.Error(), "IP allocator didn't found container"), Equals, true)
}

func (s *DaemonSuite) TestGetIPAMConfOK(c *C) {
	ciliumRoutes := []ipam.Route{
		*ipam.NewRoute(net.IPNet{IP: NodeAddr, Mask: addressing.NodeIPv6Mask}, nil),
		*ipam.NewRoute(addressing.IPv6DefaultRoute, NodeAddr),
	}

	rep := ipam.IPAMConfigRep{
		IPAMConfig: &ipam.IPAMRep{
			IP6: &ipam.IPConfig{
				Gateway: NodeAddr,
				Routes:  ciliumRoutes,
			},
		},
	}

	s.d.OnGetIPAMConf = func(ipamType ipam.IPAMType, options ipam.IPAMReq) (*ipam.IPAMConfigRep, error) {
		c.Assert(ipamType, Equals, ipam.LibnetworkIPAMType)
		c.Assert(options, Equals, ipam.IPAMReq{})
		return &rep, nil
	}

	ipamRep, err := s.c.GetIPAMConf(ipam.LibnetworkIPAMType, ipam.IPAMReq{})
	c.Assert(err, IsNil)
	c.Assert(*ipamRep, DeepEquals, rep)
}

func (s *DaemonSuite) TestGetIPAMConfFail(c *C) {
	s.d.OnGetIPAMConf = func(ipamType ipam.IPAMType, options ipam.IPAMReq) (*ipam.IPAMConfigRep, error) {
		c.Assert(ipamType, Equals, ipam.LibnetworkIPAMType)
		c.Assert(options, Equals, ipam.IPAMReq{})
		return nil, errors.New("IP allocator didn't found container")
	}

	_, err := s.c.GetIPAMConf(ipam.LibnetworkIPAMType, ipam.IPAMReq{})
	c.Assert(strings.Contains(err.Error(), "IP allocator didn't found container"), Equals, true)
}
