package client

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"

	"github.com/noironetworks/cilium-net/common"
	"github.com/noironetworks/cilium-net/common/types"

	libnetworktypes "github.com/docker/libnetwork/types"
	. "gopkg.in/check.v1"
)

func (s *CiliumNetClientSuite) TestAllocateIPOK(c *C) {
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
	cniReq := types.IPAMReq{ContainerID: "11b3354cca51cf41ef05f338ec6c1016d03f9496ff701b6060b649248ae07523"}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c.Assert(r.Method, Equals, "POST")
		c.Assert(r.URL.Path, Equals, "/allocator/ipam-allocate/"+string(types.CNIIPAMType))
		var options types.IPAMReq
		err := json.NewDecoder(r.Body).Decode(&options)
		c.Assert(err, IsNil)
		c.Assert(options, Equals, cniReq)
		w.WriteHeader(http.StatusCreated)
		err = json.NewEncoder(w).Encode(ipamConfig)
		c.Assert(err, Equals, nil)
	}))
	defer server.Close()

	cli := NewTestClient(server.URL, c)

	ipamConfigReceived, err := cli.AllocateIP(types.CNIIPAMType, cniReq)
	c.Assert(err, Equals, nil)
	c.Assert(*ipamConfigReceived, DeepEquals, ipamConfig)
}

func (s *CiliumNetClientSuite) TestAllocateIPFail(c *C) {
	cniReq := types.IPAMReq{ContainerID: "11b3354cca51cf41ef05f338ec6c1016d03f9496ff701b6060b649248ae07523"}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c.Assert(r.Method, Equals, "POST")
		c.Assert(r.URL.Path, Equals, "/allocator/ipam-allocate/"+string(types.CNIIPAMType))
		var options types.IPAMReq
		err := json.NewDecoder(r.Body).Decode(&options)
		c.Assert(err, IsNil)
		c.Assert(options, Equals, cniReq)
		w.WriteHeader(http.StatusNotFound)
		w.Header().Set("Content-Type", "application/json")
		err = json.NewEncoder(w).Encode(types.ServerError{-1, "the daemon has died"})
		c.Assert(err, Equals, nil)
	}))
	defer server.Close()

	cli := NewTestClient(server.URL, c)

	_, err := cli.AllocateIP(types.CNIIPAMType, cniReq)
	c.Assert(strings.Contains(err.Error(), "the daemon has died"), Equals, true)
}

func (s *CiliumNetClientSuite) TestReleaseIPOK(c *C) {
	cniReq := types.IPAMReq{ContainerID: "11b3354cca51cf41ef05f338ec6c1016d03f9496ff701b6060b649248ae07523"}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c.Assert(r.Method, Equals, "POST")
		c.Assert(r.URL.Path, Equals, "/allocator/ipam-release/"+string(types.CNIIPAMType))
		var options types.IPAMReq
		err := json.NewDecoder(r.Body).Decode(&options)
		c.Assert(err, IsNil)
		c.Assert(options, DeepEquals, cniReq)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	cli := NewTestClient(server.URL, c)

	err := cli.ReleaseIP(types.CNIIPAMType, cniReq)
	c.Assert(err, Equals, nil)
}

func (s *CiliumNetClientSuite) TestReleaseIPFail(c *C) {
	cniReq := types.IPAMReq{ContainerID: "11b3354cca51cf41ef05f338ec6c1016d03f9496ff701b6060b649248ae07523"}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c.Assert(r.Method, Equals, "POST")
		c.Assert(r.URL.Path, Equals, "/allocator/ipam-release/"+string(types.CNIIPAMType))
		var options types.IPAMReq
		err := json.NewDecoder(r.Body).Decode(&options)
		c.Assert(err, IsNil)
		c.Assert(options, DeepEquals, cniReq)
		w.WriteHeader(http.StatusInternalServerError)
		w.Header().Set("Content-Type", "application/json")
		err = json.NewEncoder(w).Encode(types.ServerError{-1, "daemon didn't complete your request"})
		c.Assert(err, Equals, nil)
	}))
	defer server.Close()

	cli := NewTestClient(server.URL, c)

	err := cli.ReleaseIP(types.CNIIPAMType, cniReq)
	c.Assert(strings.Contains(err.Error(), "daemon didn't complete your request"), Equals, true)
}
