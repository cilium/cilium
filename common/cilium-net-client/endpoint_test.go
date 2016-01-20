package cilium_net_client

import (
	"net/http"
	"net/http/httptest"
	"strings"

	"github.com/noironetworks/cilium-net/common/types"

	"github.com/docker/docker/vendor/src/github.com/jfrazelle/go/canonical/json"
	. "github.com/noironetworks/cilium-net/Godeps/_workspace/src/gopkg.in/check.v1"
)

func (s *CiliumNetClientSuite) TestEndpointCreateOK(c *C) {
	ep := types.Endpoint{
		LxcMAC:        HardAddr,
		LxcIP:         EpAddr,
		NodeIP:        NodeAddr,
		Ifname:        "ifname",
		SecCtx:        "secctx",
		DockerNetwork: "dockernetwork",
	}
	ep.SetID()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c.Assert(r.Method, Equals, "POST")
		c.Assert(r.URL.Path, Equals, "/endpoint/4370") //0x1112
		d := json.NewDecoder(r.Body)
		var receivedEp types.Endpoint
		err := d.Decode(&receivedEp)
		c.Assert(err, Equals, nil)
		c.Assert(receivedEp, DeepEquals, ep)
		w.WriteHeader(http.StatusCreated)
	}))
	defer server.Close()

	cli := NewTestClient(server.URL, c)

	err := cli.EndpointJoin(ep)

	c.Assert(err, Equals, nil)
}

func (s *CiliumNetClientSuite) TestEndpointCreateFail(c *C) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c.Assert(r.Method, Equals, "POST")
		c.Assert(r.URL.Path, Equals, "/endpoint/4370") //0x1112
		w.WriteHeader(http.StatusNotFound)
		w.Header().Set("Content-Type", "application/json")
		e := json.NewEncoder(w)
		err := e.Encode(types.ServerError{-1, "the daemon has died"})
		c.Assert(err, Equals, nil)
	}))
	defer server.Close()

	cli := NewTestClient(server.URL, c)

	ep := types.Endpoint{
		LxcMAC:        HardAddr,
		LxcIP:         EpAddr,
		NodeIP:        NodeAddr,
		Ifname:        "ifname",
		SecCtx:        "secctx",
		DockerNetwork: "dockernetwork",
	}
	ep.SetID()

	err := cli.EndpointJoin(ep)

	c.Assert(strings.Contains(err.Error(), "the daemon has died"), Equals, true)
}

func (s *CiliumNetClientSuite) TestEndpointLeaveOK(c *C) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c.Assert(r.Method, Equals, "DELETE")
		c.Assert(r.URL.Path, Equals, "/endpoint/4370") //0x1112
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	cli := NewTestClient(server.URL, c)

	ep := types.Endpoint{
		LxcMAC:        HardAddr,
		LxcIP:         EpAddr,
		NodeIP:        NodeAddr,
		Ifname:        "eth0",
		SecCtx:        "secctx",
		DockerNetwork: "dockernetwork",
	}
	ep.SetID()

	err := cli.EndpointLeave(ep)

	c.Assert(err, Equals, nil)
}

func (s *CiliumNetClientSuite) TestEndpointLeaveFail(c *C) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c.Assert(r.Method, Equals, "DELETE")
		c.Assert(r.URL.Path, Equals, "/endpoint/4370") //0x1112
		w.WriteHeader(http.StatusBadRequest)
		w.Header().Set("Content-Type", "application/json")
		e := json.NewEncoder(w)
		err := e.Encode(types.ServerError{-1, "daemon didn't complete your request"})
		c.Assert(err, Equals, nil)
	}))
	defer server.Close()

	cli := NewTestClient(server.URL, c)

	ep := types.Endpoint{
		LxcMAC:        HardAddr,
		LxcIP:         EpAddr,
		NodeIP:        NodeAddr,
		Ifname:        "eth0",
		SecCtx:        "secctx",
		DockerNetwork: "dockernetwork",
	}
	ep.SetID()

	err := cli.EndpointLeave(ep)

	c.Assert(strings.Contains(err.Error(), "daemon didn't complete your request"), Equals, true)
}
