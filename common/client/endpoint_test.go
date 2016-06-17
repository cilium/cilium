package client

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"time"

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

func (s *CiliumNetClientSuite) TestEndpointJoinOK(c *C) {
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

func (s *CiliumNetClientSuite) TestEndpointJoinFail(c *C) {
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
		LXCMAC:          HardAddr,
		LXCIP:           EpAddr,
		NodeMAC:         HardAddr,
		NodeIP:          NodeAddr,
		IfName:          "ifname",
		DockerNetworkID: "dockernetwork",
		SecLabel:        SecLabel,
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
		LXCMAC:          HardAddr,
		LXCIP:           EpAddr,
		NodeMAC:         HardAddr,
		NodeIP:          NodeAddr,
		IfName:          "eth0",
		DockerNetworkID: "dockernetwork",
		SecLabel:        SecLabel,
	}
	ep.SetID()

	err := cli.EndpointLeave(ep.ID)

	c.Assert(err, Equals, nil)
}

func (s *CiliumNetClientSuite) TestEndpointLeaveFail(c *C) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c.Assert(r.Method, Equals, "DELETE")
		c.Assert(r.URL.Path, Equals, "/endpoint/4370") //0x1112
		w.WriteHeader(http.StatusCreated)
		w.Header().Set("Content-Type", "application/json")
		e := json.NewEncoder(w)
		err := e.Encode(types.ServerError{-1, "daemon didn't complete your request"})
		c.Assert(err, Equals, nil)
	}))
	defer server.Close()

	cli := NewTestClient(server.URL, c)

	ep := types.Endpoint{
		LXCMAC:          HardAddr,
		LXCIP:           EpAddr,
		NodeMAC:         HardAddr,
		NodeIP:          NodeAddr,
		IfName:          "eth0",
		DockerNetworkID: "dockernetwork",
		SecLabel:        SecLabel,
	}
	ep.SetID()

	err := cli.EndpointLeave(ep.ID)

	c.Log(err.Error())
	c.Assert(strings.Contains(err.Error(), "daemon didn't complete your request"), Equals, true)
}

func (s *CiliumNetClientSuite) TestEndpointLeaveByDockerEPIDOK(c *C) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c.Assert(r.Method, Equals, "DELETE")
		c.Assert(r.URL.Path, Equals, "/endpoint-by-docker-ep-id/4370") //0x1112
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	cli := NewTestClient(server.URL, c)

	ep := types.Endpoint{
		LXCMAC:           HardAddr,
		LXCIP:            EpAddr,
		NodeMAC:          HardAddr,
		NodeIP:           NodeAddr,
		IfName:           "eth0",
		DockerNetworkID:  "dockernetwork",
		SecLabel:         SecLabel,
		DockerEndpointID: "4370",
	}
	ep.SetID()

	err := cli.EndpointLeaveByDockerEPID(ep.DockerEndpointID)

	c.Assert(err, Equals, nil)
}

func (s *CiliumNetClientSuite) TestEndpointLeaveByDockerEPIDFail(c *C) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c.Assert(r.Method, Equals, "DELETE")
		c.Assert(r.URL.Path, Equals, "/endpoint-by-docker-ep-id/4370") //0x1112
		w.WriteHeader(http.StatusCreated)
		w.Header().Set("Content-Type", "application/json")
		e := json.NewEncoder(w)
		err := e.Encode(types.ServerError{-1, "daemon didn't complete your request"})
		c.Assert(err, Equals, nil)
	}))
	defer server.Close()

	cli := NewTestClient(server.URL, c)

	ep := types.Endpoint{
		LXCMAC:           HardAddr,
		LXCIP:            EpAddr,
		NodeMAC:          HardAddr,
		NodeIP:           NodeAddr,
		IfName:           "eth0",
		DockerNetworkID:  "dockernetwork",
		SecLabel:         SecLabel,
		DockerEndpointID: "4370",
	}
	ep.SetID()

	err := cli.EndpointLeaveByDockerEPID(ep.DockerEndpointID)

	c.Log(err.Error())
	c.Assert(strings.Contains(err.Error(), "daemon didn't complete your request"), Equals, true)
}

func (s *CiliumNetClientSuite) TestEndpointGetOK(c *C) {
	epOut := types.Endpoint{
		LXCMAC:          HardAddr,
		LXCIP:           EpAddr,
		NodeMAC:         HardAddr,
		NodeIP:          NodeAddr,
		IfName:          "eth0",
		DockerNetworkID: "dockernetwork",
		SecLabel:        SecLabel,
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c.Assert(r.Method, Equals, "GET")
		c.Assert(r.URL.Path, Equals, "/endpoint/4370") //0x1112
		w.WriteHeader(http.StatusOK)
		err := json.NewEncoder(w).Encode(epOut)
		c.Assert(err, IsNil)
	}))
	defer server.Close()

	cli := NewTestClient(server.URL, c)

	ep, err := cli.EndpointGet("4370")
	c.Assert(err, IsNil)
	c.Assert(*ep, DeepEquals, epOut)

	// Not found
	server2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c.Assert(r.Method, Equals, "GET")
		c.Assert(r.URL.Path, Equals, "/endpoint/4371") //0x1112
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server2.Close()
	cli = NewTestClient(server2.URL, c)

	ep2, err := cli.EndpointGet("4371")
	c.Assert(err, IsNil)
	c.Assert(ep2, IsNil)
}

func (s *CiliumNetClientSuite) TestEndpointGetFail(c *C) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c.Assert(r.Method, Equals, "GET")
		c.Assert(r.URL.Path, Equals, "/endpoint/4370") //0x1112
		w.WriteHeader(http.StatusInternalServerError)
		w.Header().Set("Content-Type", "application/json")
		err := json.NewEncoder(w).Encode(types.ServerError{-1, "daemon didn't complete your request"})
		c.Assert(err, Equals, nil)
	}))
	defer server.Close()

	cli := NewTestClient(server.URL, c)

	ep, err := cli.EndpointGet("4370")
	c.Assert(strings.Contains(err.Error(), "daemon didn't complete your request"), Equals, true)
	c.Assert(ep, IsNil)
}

func (s *CiliumNetClientSuite) TestEndpointGetByDockerEPIDOK(c *C) {
	epOut := types.Endpoint{
		LXCMAC:          HardAddr,
		LXCIP:           EpAddr,
		NodeMAC:         HardAddr,
		NodeIP:          NodeAddr,
		IfName:          "eth0",
		DockerNetworkID: "dockernetwork",
		SecLabel:        SecLabel,
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c.Assert(r.Method, Equals, "GET")
		c.Assert(r.URL.Path, Equals, "/endpoint-by-docker-ep-id/4370") //0x1112
		w.WriteHeader(http.StatusOK)
		err := json.NewEncoder(w).Encode(epOut)
		c.Assert(err, IsNil)
	}))
	defer server.Close()

	cli := NewTestClient(server.URL, c)

	ep, err := cli.EndpointGetByDockerEPID("4370")
	c.Assert(err, IsNil)
	c.Assert(*ep, DeepEquals, epOut)

	// Not found
	server2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c.Assert(r.Method, Equals, "GET")
		c.Assert(r.URL.Path, Equals, "/endpoint-by-docker-ep-id/4371") //0x1112
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server2.Close()
	cli = NewTestClient(server2.URL, c)

	ep2, err := cli.EndpointGetByDockerEPID("4371")
	c.Assert(err, IsNil)
	c.Assert(ep2, IsNil)
}

func (s *CiliumNetClientSuite) TestEndpointGetByDockerEPIDFail(c *C) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c.Assert(r.Method, Equals, "GET")
		c.Assert(r.URL.Path, Equals, "/endpoint-by-docker-ep-id/4370") //0x1112
		w.WriteHeader(http.StatusInternalServerError)
		w.Header().Set("Content-Type", "application/json")
		err := json.NewEncoder(w).Encode(types.ServerError{-1, "daemon didn't complete your request"})
		c.Assert(err, Equals, nil)
	}))
	defer server.Close()

	cli := NewTestClient(server.URL, c)

	ep, err := cli.EndpointGetByDockerEPID("4370")
	c.Assert(strings.Contains(err.Error(), "daemon didn't complete your request"), Equals, true)
	c.Assert(ep, IsNil)
}

func (s *CiliumNetClientSuite) TestEndpointsGetOK(c *C) {
	epsOut := []types.Endpoint{
		types.Endpoint{
			LXCMAC:          HardAddr,
			LXCIP:           EpAddr,
			NodeMAC:         HardAddr,
			NodeIP:          NodeAddr,
			IfName:          "eth0",
			DockerNetworkID: "dockernetwork",
			SecLabel:        SecLabel,
		},
		types.Endpoint{
			LXCMAC:          HardAddr,
			LXCIP:           EpAddr,
			NodeMAC:         HardAddr,
			NodeIP:          NodeAddr,
			IfName:          "eth0",
			DockerNetworkID: "dockernetwork",
			SecLabel:        SecLabel,
		},
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c.Assert(r.Method, Equals, "GET")
		c.Assert(r.URL.Path, Equals, "/endpoints")
		w.WriteHeader(http.StatusOK)
		err := json.NewEncoder(w).Encode(epsOut)
		c.Assert(err, IsNil)
	}))
	defer server.Close()

	cli := NewTestClient(server.URL, c)

	eps, err := cli.EndpointsGet()
	c.Assert(err, IsNil)
	c.Assert(eps, DeepEquals, epsOut)

	// Not found
	server2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c.Assert(r.Method, Equals, "GET")
		c.Assert(r.URL.Path, Equals, "/endpoints")
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server2.Close()
	cli = NewTestClient(server2.URL, c)

	ep2, err := cli.EndpointsGet()
	c.Assert(err, IsNil)
	c.Assert(ep2, IsNil)
}

func (s *CiliumNetClientSuite) TestEndpointsGetFail(c *C) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c.Assert(r.Method, Equals, "GET")
		c.Assert(r.URL.Path, Equals, "/endpoints")
		w.WriteHeader(http.StatusInternalServerError)
		w.Header().Set("Content-Type", "application/json")
		err := json.NewEncoder(w).Encode(types.ServerError{-1, "daemon didn't complete your request"})
		c.Assert(err, Equals, nil)
	}))
	defer server.Close()

	cli := NewTestClient(server.URL, c)

	eps, err := cli.EndpointsGet()
	c.Assert(strings.Contains(err.Error(), "daemon didn't complete your request"), Equals, true)
	c.Assert(eps, IsNil)
}

func (s *CiliumNetClientSuite) TestEndpointUpdateOK(c *C) {
	optsWanted := types.EPOpts{"FOO": true}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c.Assert(r.Method, Equals, "POST")
		c.Assert(r.URL.Path, Equals, "/endpoint/update/4370") //0x1112
		var opts types.EPOpts
		err := json.NewDecoder(r.Body).Decode(&opts)
		c.Assert(err, IsNil)
		c.Assert(opts, DeepEquals, optsWanted)
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()

	cli := NewTestClient(server.URL, c)

	err := cli.EndpointUpdate("4370", optsWanted)
	c.Assert(err, IsNil)

	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c.Assert(r.Method, Equals, "POST")
		c.Assert(r.URL.Path, Equals, "/endpoint/update/4370") //0x1112
		var opts types.EPOpts
		err := json.NewDecoder(r.Body).Decode(&opts)
		c.Assert(err, IsNil)
		c.Assert(opts, IsNil)
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()

	cli = NewTestClient(server.URL, c)
	err = cli.EndpointUpdate("4370", nil)
	c.Assert(err, IsNil)
}

func (s *CiliumNetClientSuite) TestEndpointUpdateFail(c *C) {
	optsWanted := types.EPOpts{"FOO": true}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c.Assert(r.Method, Equals, "POST")
		c.Assert(r.URL.Path, Equals, "/endpoint/update/4370") //0x1112
		w.WriteHeader(http.StatusNotFound)
		w.Header().Set("Content-Type", "application/json")
		err := json.NewEncoder(w).Encode(types.ServerError{-1, "the daemon has died"})
		c.Assert(err, IsNil)
	}))
	defer server.Close()

	cli := NewTestClient(server.URL, c)

	err := cli.EndpointUpdate("4370", optsWanted)
	c.Assert(strings.Contains(err.Error(), "the daemon has died"), Equals, true)
}

func (s *CiliumNetClientSuite) TestEndpointSaveOK(c *C) {
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

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c.Assert(r.Method, Equals, "POST")
		c.Assert(r.URL.Path, Equals, "/endpoint/save/4370") //0x1112
		d := json.NewDecoder(r.Body)
		var receivedEp types.Endpoint
		err := d.Decode(&receivedEp)
		c.Assert(err, Equals, nil)
		c.Assert(receivedEp, DeepEquals, ep)
		w.WriteHeader(http.StatusCreated)
	}))
	defer server.Close()

	cli := NewTestClient(server.URL, c)

	err := cli.EndpointSave(ep)

	c.Assert(err, IsNil)
}

func (s *CiliumNetClientSuite) TestEndpointSaveFail(c *C) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c.Assert(r.Method, Equals, "POST")
		c.Assert(r.URL.Path, Equals, "/endpoint/save/4370") //0x1112
		w.WriteHeader(http.StatusNotFound)
		w.Header().Set("Content-Type", "application/json")
		e := json.NewEncoder(w)
		err := e.Encode(types.ServerError{-1, "the daemon has died"})
		c.Assert(err, Equals, nil)
	}))
	defer server.Close()

	cli := NewTestClient(server.URL, c)

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

	err := cli.EndpointSave(ep)

	c.Assert(strings.Contains(err.Error(), "the daemon has died"), Equals, true)
}
