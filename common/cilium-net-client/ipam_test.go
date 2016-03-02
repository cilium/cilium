package cilium_net_client

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"

	"github.com/noironetworks/cilium-net/common"
	"github.com/noironetworks/cilium-net/common/types"

	libnetworktypes "github.com/noironetworks/cilium-net/Godeps/_workspace/src/github.com/docker/libnetwork/types"
	. "github.com/noironetworks/cilium-net/Godeps/_workspace/src/gopkg.in/check.v1"
)

func (s *CiliumNetClientSuite) TestGetIPsOK(c *C) {
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
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c.Assert(r.Method, Equals, "PUT")
		c.Assert(r.URL.Path, Equals, "/allocator/container/11b3354cca51cf41ef05f338ec6c1016d03f9496ff701b6060b649248ae07523")
		w.WriteHeader(http.StatusCreated)
		e := json.NewEncoder(w)
		err := e.Encode(ipamConfig)
		c.Assert(err, Equals, nil)
	}))
	defer server.Close()

	cli := NewTestClient(server.URL, c)

	ipamConfigReceived, err := cli.AllocateIPs("11b3354cca51cf41ef05f338ec6c1016d03f9496ff701b6060b649248ae07523")
	c.Assert(err, Equals, nil)
	c.Assert(*ipamConfigReceived, DeepEquals, ipamConfig)
}

func (s *CiliumNetClientSuite) TestGetIPsFail(c *C) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c.Assert(r.Method, Equals, "PUT")
		c.Assert(r.URL.Path, Equals, "/allocator/container/11b3354cca51cf41ef05f338ec6c1016d03f9496ff701b6060b649248ae07523")
		w.WriteHeader(http.StatusNotFound)
		w.Header().Set("Content-Type", "application/json")
		e := json.NewEncoder(w)
		err := e.Encode(types.ServerError{-1, "the daemon has died"})
		c.Assert(err, Equals, nil)
	}))
	defer server.Close()

	cli := NewTestClient(server.URL, c)

	_, err := cli.AllocateIPs("11b3354cca51cf41ef05f338ec6c1016d03f9496ff701b6060b649248ae07523")
	c.Assert(strings.Contains(err.Error(), "the daemon has died"), Equals, true)
}

func (s *CiliumNetClientSuite) TestReleaseIPsOK(c *C) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c.Assert(r.Method, Equals, "DELETE")
		c.Assert(r.URL.Path, Equals, "/allocator/container/11b3354cca51cf41ef05f338ec6c1016d03f9496ff701b6060b649248ae07523")
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	cli := NewTestClient(server.URL, c)

	err := cli.ReleaseIPs("11b3354cca51cf41ef05f338ec6c1016d03f9496ff701b6060b649248ae07523")
	c.Assert(err, Equals, nil)
}

func (s *CiliumNetClientSuite) TestReleaseIPsFail(c *C) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c.Assert(r.Method, Equals, "DELETE")
		c.Assert(r.URL.Path, Equals, "/allocator/container/11b3354cca51cf41ef05f338ec6c1016d03f9496ff701b6060b649248ae07523")
		w.WriteHeader(http.StatusInternalServerError)
		w.Header().Set("Content-Type", "application/json")
		e := json.NewEncoder(w)
		err := e.Encode(types.ServerError{-1, "daemon didn't complete your request"})
		c.Assert(err, Equals, nil)
	}))
	defer server.Close()

	cli := NewTestClient(server.URL, c)

	err := cli.ReleaseIPs("11b3354cca51cf41ef05f338ec6c1016d03f9496ff701b6060b649248ae07523")
	c.Assert(strings.Contains(err.Error(), "daemon didn't complete your request"), Equals, true)
}
