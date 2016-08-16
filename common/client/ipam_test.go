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
package client

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"

	"github.com/cilium/cilium/common/addressing"
	"github.com/cilium/cilium/common/ipam"
	"github.com/cilium/cilium/common/types"

	libnetworktypes "github.com/docker/libnetwork/types"
	. "gopkg.in/check.v1"
)

func (s *CiliumNetClientSuite) TestAllocateIPOK(c *C) {
	ipamConfig := ipam.IPAMRep{
		IP6: &ipam.IPConfig{
			Gateway: NodeAddr,
			IP:      net.IPNet{IP: IPv6Addr.IP(), Mask: addressing.NodeIPv6Mask},
			Routes: []ipam.Route{
				ipam.Route{
					Destination: addressing.IPv6DefaultRoute,
					NextHop:     nil,
					Type:        libnetworktypes.CONNECTED,
				},
			},
		},
	}
	cniReq := ipam.IPAMReq{ContainerID: "11b3354cca51cf41ef05f338ec6c1016d03f9496ff701b6060b649248ae07523"}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c.Assert(r.Method, Equals, "POST")
		c.Assert(r.URL.Path, Equals, "/allocator/ipam-allocate/"+string(ipam.CNIIPAMType))
		var options ipam.IPAMReq
		err := json.NewDecoder(r.Body).Decode(&options)
		c.Assert(err, IsNil)
		c.Assert(options, Equals, cniReq)
		w.WriteHeader(http.StatusCreated)
		err = json.NewEncoder(w).Encode(ipamConfig)
		c.Assert(err, Equals, nil)
	}))
	defer server.Close()

	cli := NewTestClient(server.URL, c)

	ipamConfigReceived, err := cli.AllocateIP(ipam.CNIIPAMType, cniReq)
	c.Assert(err, Equals, nil)
	c.Assert(*ipamConfigReceived, DeepEquals, ipamConfig)
}

func (s *CiliumNetClientSuite) TestAllocateIPFail(c *C) {
	cniReq := ipam.IPAMReq{ContainerID: "11b3354cca51cf41ef05f338ec6c1016d03f9496ff701b6060b649248ae07523"}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c.Assert(r.Method, Equals, "POST")
		c.Assert(r.URL.Path, Equals, "/allocator/ipam-allocate/"+string(ipam.CNIIPAMType))
		var options ipam.IPAMReq
		err := json.NewDecoder(r.Body).Decode(&options)
		c.Assert(err, IsNil)
		c.Assert(options, Equals, cniReq)
		w.WriteHeader(http.StatusNotFound)
		w.Header().Set("Content-Type", "application/json")
		err = json.NewEncoder(w).Encode(types.ServerError{Code: -1, Text: "the daemon has died"})
		c.Assert(err, Equals, nil)
	}))
	defer server.Close()

	cli := NewTestClient(server.URL, c)

	_, err := cli.AllocateIP(ipam.CNIIPAMType, cniReq)
	c.Assert(strings.Contains(err.Error(), "the daemon has died"), Equals, true)
}

func (s *CiliumNetClientSuite) TestReleaseIPOK(c *C) {
	cniReq := ipam.IPAMReq{ContainerID: "11b3354cca51cf41ef05f338ec6c1016d03f9496ff701b6060b649248ae07523"}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c.Assert(r.Method, Equals, "POST")
		c.Assert(r.URL.Path, Equals, "/allocator/ipam-release/"+string(ipam.CNIIPAMType))
		var options ipam.IPAMReq
		err := json.NewDecoder(r.Body).Decode(&options)
		c.Assert(err, IsNil)
		c.Assert(options, DeepEquals, cniReq)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	cli := NewTestClient(server.URL, c)

	err := cli.ReleaseIP(ipam.CNIIPAMType, cniReq)
	c.Assert(err, Equals, nil)
}

func (s *CiliumNetClientSuite) TestReleaseIPFail(c *C) {
	cniReq := ipam.IPAMReq{ContainerID: "11b3354cca51cf41ef05f338ec6c1016d03f9496ff701b6060b649248ae07523"}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c.Assert(r.Method, Equals, "POST")
		c.Assert(r.URL.Path, Equals, "/allocator/ipam-release/"+string(ipam.CNIIPAMType))
		var options ipam.IPAMReq
		err := json.NewDecoder(r.Body).Decode(&options)
		c.Assert(err, IsNil)
		c.Assert(options, DeepEquals, cniReq)
		w.WriteHeader(http.StatusInternalServerError)
		w.Header().Set("Content-Type", "application/json")
		err = json.NewEncoder(w).Encode(types.ServerError{Code: -1, Text: "daemon didn't complete your request"})
		c.Assert(err, Equals, nil)
	}))
	defer server.Close()

	cli := NewTestClient(server.URL, c)

	err := cli.ReleaseIP(ipam.CNIIPAMType, cniReq)
	c.Assert(strings.Contains(err.Error(), "daemon didn't complete your request"), Equals, true)
}

func (s *CiliumNetClientSuite) TestGetIPAMConfOK(c *C) {
	cniReq := ipam.IPAMReq{}
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

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c.Assert(r.Method, Equals, "POST")
		c.Assert(r.URL.Path, Equals, "/allocator/ipam-configuration/"+string(ipam.LibnetworkIPAMType))
		var options ipam.IPAMReq
		err := json.NewDecoder(r.Body).Decode(&options)
		c.Assert(err, IsNil)
		c.Assert(options, DeepEquals, cniReq)
		w.WriteHeader(http.StatusOK)
		err = json.NewEncoder(w).Encode(rep)
		c.Assert(err, Equals, nil)
	}))
	defer server.Close()

	cli := NewTestClient(server.URL, c)

	ipamRep, err := cli.GetIPAMConf(ipam.LibnetworkIPAMType, cniReq)
	c.Assert(err, Equals, nil)
	c.Assert(*ipamRep, DeepEquals, rep)
}

func (s *CiliumNetClientSuite) TestGetIPAMConfFail(c *C) {
	cniReq := ipam.IPAMReq{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c.Assert(r.Method, Equals, "POST")
		c.Assert(r.URL.Path, Equals, "/allocator/ipam-configuration/"+string(ipam.CNIIPAMType))
		var options ipam.IPAMReq
		err := json.NewDecoder(r.Body).Decode(&options)
		c.Assert(err, IsNil)
		c.Assert(options, DeepEquals, cniReq)
		w.WriteHeader(http.StatusInternalServerError)
		w.Header().Set("Content-Type", "application/json")
		err = json.NewEncoder(w).Encode(types.ServerError{Code: -1, Text: "daemon didn't complete your request"})
		c.Assert(err, Equals, nil)
	}))
	defer server.Close()

	cli := NewTestClient(server.URL, c)

	_, err := cli.GetIPAMConf(ipam.CNIIPAMType, cniReq)
	c.Assert(strings.Contains(err.Error(), "daemon didn't complete your request"), Equals, true)
}
