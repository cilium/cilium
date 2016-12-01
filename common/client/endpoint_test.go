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
	"time"

	"github.com/cilium/cilium/common/addressing"
	"github.com/cilium/cilium/common/types"

	. "gopkg.in/check.v1"
)

var (
	IPv6Addr, _ = addressing.NewCiliumIPv6("beef:beef:beef:beef:aaaa:aaaa:1111:1112")
	IPv4Addr, _ = addressing.NewCiliumIPv4("10.11.12.13")
	NodeAddr    = net.IP{0xbe, 0xef, 0xbe, 0xef, 0xbe, 0xef, 0xbe, 0xef, 0xaa, 0xaa, 0xaa, 0xaa, 0x11, 0x11, 0, 0}
	HardAddr    = types.MAC{0x01, 0x02, 0x03, 0x04, 0x05, 0x06}
	SecLabel    = &types.SecCtxLabel{
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
		IPv6:            IPv6Addr,
		IPv4:            IPv4Addr,
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
		err := e.Encode(types.ServerError{Code: -1, Text: "the daemon has died"})
		c.Assert(err, Equals, nil)
	}))
	defer server.Close()

	cli := NewTestClient(server.URL, c)

	ep := types.Endpoint{
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
		IPv6:            IPv6Addr,
		IPv4:            IPv4Addr,
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
		err := e.Encode(types.ServerError{Code: -1, Text: "daemon didn't complete your request"})
		c.Assert(err, Equals, nil)
	}))
	defer server.Close()

	cli := NewTestClient(server.URL, c)

	ep := types.Endpoint{
		LXCMAC:          HardAddr,
		IPv6:            IPv6Addr,
		IPv4:            IPv4Addr,
		NodeMAC:         HardAddr,
		NodeIP:          NodeAddr,
		IfName:          "eth0",
		DockerNetworkID: "dockernetwork",
		SecLabel:        SecLabel,
	}
	ep.SetID()

	err := cli.EndpointLeave(ep.ID)

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
		IPv6:             IPv6Addr,
		IPv4:             IPv4Addr,
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
		err := e.Encode(types.ServerError{Code: -1, Text: "daemon didn't complete your request"})
		c.Assert(err, Equals, nil)
	}))
	defer server.Close()

	cli := NewTestClient(server.URL, c)

	ep := types.Endpoint{
		LXCMAC:           HardAddr,
		IPv6:             IPv6Addr,
		IPv4:             IPv4Addr,
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
		IPv6:            IPv6Addr,
		IPv4:            IPv4Addr,
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

	ep, err := cli.EndpointGet(4370)
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

	ep2, err := cli.EndpointGet(4371)
	c.Assert(err, IsNil)
	c.Assert(ep2, IsNil)
}

func (s *CiliumNetClientSuite) TestEndpointGetFail(c *C) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c.Assert(r.Method, Equals, "GET")
		c.Assert(r.URL.Path, Equals, "/endpoint/4370") //0x1112
		w.WriteHeader(http.StatusInternalServerError)
		w.Header().Set("Content-Type", "application/json")
		err := json.NewEncoder(w).Encode(types.ServerError{Code: -1, Text: "daemon didn't complete your request"})
		c.Assert(err, Equals, nil)
	}))
	defer server.Close()

	cli := NewTestClient(server.URL, c)

	ep, err := cli.EndpointGet(4370)
	c.Assert(strings.Contains(err.Error(), "daemon didn't complete your request"), Equals, true)
	c.Assert(ep, IsNil)
}

func (s *CiliumNetClientSuite) TestEndpointGetByDockerEPIDOK(c *C) {
	epOut := types.Endpoint{
		LXCMAC:          HardAddr,
		IPv6:            IPv6Addr,
		IPv4:            IPv4Addr,
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
		err := json.NewEncoder(w).Encode(types.ServerError{Code: -1, Text: "daemon didn't complete your request"})
		c.Assert(err, Equals, nil)
	}))
	defer server.Close()

	cli := NewTestClient(server.URL, c)

	ep, err := cli.EndpointGetByDockerEPID("4370")
	c.Assert(strings.Contains(err.Error(), "daemon didn't complete your request"), Equals, true)
	c.Assert(ep, IsNil)
}

func (s *CiliumNetClientSuite) TestEndpointGetByDockerIDOK(c *C) {
	epOut := types.Endpoint{
		LXCMAC:          HardAddr,
		IPv6:            IPv6Addr,
		IPv4:            IPv4Addr,
		NodeMAC:         HardAddr,
		NodeIP:          NodeAddr,
		IfName:          "eth0",
		DockerNetworkID: "dockernetwork",
		SecLabel:        SecLabel,
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c.Assert(r.Method, Equals, "GET")
		c.Assert(r.URL.Path, Equals, "/endpoint-by-docker-id/4370") //0x1112
		w.WriteHeader(http.StatusOK)
		err := json.NewEncoder(w).Encode(epOut)
		c.Assert(err, IsNil)
	}))
	defer server.Close()

	cli := NewTestClient(server.URL, c)

	ep, err := cli.EndpointGetByDockerID("4370")
	c.Assert(err, IsNil)
	c.Assert(*ep, DeepEquals, epOut)

	// Not found
	server2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c.Assert(r.Method, Equals, "GET")
		c.Assert(r.URL.Path, Equals, "/endpoint-by-docker-id/4371") //0x1112
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server2.Close()
	cli = NewTestClient(server2.URL, c)

	ep2, err := cli.EndpointGetByDockerID("4371")
	c.Assert(err, IsNil)
	c.Assert(ep2, IsNil)
}

func (s *CiliumNetClientSuite) TestEndpointGetByDockerIDFail(c *C) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c.Assert(r.Method, Equals, "GET")
		c.Assert(r.URL.Path, Equals, "/endpoint-by-docker-id/4370") //0x1112
		w.WriteHeader(http.StatusInternalServerError)
		w.Header().Set("Content-Type", "application/json")
		err := json.NewEncoder(w).Encode(types.ServerError{Code: -1, Text: "daemon didn't complete your request"})
		c.Assert(err, Equals, nil)
	}))
	defer server.Close()

	cli := NewTestClient(server.URL, c)

	ep, err := cli.EndpointGetByDockerID("4370")
	c.Assert(strings.Contains(err.Error(), "daemon didn't complete your request"), Equals, true)
	c.Assert(ep, IsNil)
}

func (s *CiliumNetClientSuite) TestEndpointsGetOK(c *C) {
	epsOut := []types.Endpoint{
		{
			LXCMAC:          HardAddr,
			IPv6:            IPv6Addr,
			IPv4:            IPv4Addr,
			NodeMAC:         HardAddr,
			NodeIP:          NodeAddr,
			IfName:          "eth0",
			DockerNetworkID: "dockernetwork",
			SecLabel:        SecLabel,
		},
		{
			LXCMAC:          HardAddr,
			IPv6:            IPv6Addr,
			IPv4:            IPv4Addr,
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
		err := json.NewEncoder(w).Encode(types.ServerError{Code: -1, Text: "daemon didn't complete your request"})
		c.Assert(err, Equals, nil)
	}))
	defer server.Close()

	cli := NewTestClient(server.URL, c)

	eps, err := cli.EndpointsGet()
	c.Assert(strings.Contains(err.Error(), "daemon didn't complete your request"), Equals, true)
	c.Assert(eps, IsNil)
}

func (s *CiliumNetClientSuite) TestEndpointUpdateOK(c *C) {
	optsWanted := types.OptionMap{"FOO": true}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c.Assert(r.Method, Equals, "POST")
		c.Assert(r.URL.Path, Equals, "/endpoint/update/4370") //0x1112
		var opts types.OptionMap
		err := json.NewDecoder(r.Body).Decode(&opts)
		c.Assert(err, IsNil)
		c.Assert(opts, DeepEquals, optsWanted)
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()

	cli := NewTestClient(server.URL, c)

	err := cli.EndpointUpdate(4370, optsWanted)
	c.Assert(err, IsNil)

	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c.Assert(r.Method, Equals, "POST")
		c.Assert(r.URL.Path, Equals, "/endpoint/update/4370") //0x1112
		var opts types.OptionMap
		err := json.NewDecoder(r.Body).Decode(&opts)
		c.Assert(err, IsNil)
		c.Assert(opts, IsNil)
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()

	cli = NewTestClient(server.URL, c)
	err = cli.EndpointUpdate(4370, nil)
	c.Assert(err, IsNil)
}

func (s *CiliumNetClientSuite) TestEndpointUpdateFail(c *C) {
	optsWanted := types.OptionMap{"FOO": true}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c.Assert(r.Method, Equals, "POST")
		c.Assert(r.URL.Path, Equals, "/endpoint/update/4370") //0x1112
		w.WriteHeader(http.StatusNotFound)
		w.Header().Set("Content-Type", "application/json")
		err := json.NewEncoder(w).Encode(types.ServerError{Code: -1, Text: "the daemon has died"})
		c.Assert(err, IsNil)
	}))
	defer server.Close()

	cli := NewTestClient(server.URL, c)

	err := cli.EndpointUpdate(4370, optsWanted)
	c.Assert(strings.Contains(err.Error(), "the daemon has died"), Equals, true)
}

func (s *CiliumNetClientSuite) TestEndpointSaveOK(c *C) {
	ep := types.Endpoint{
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
		err := e.Encode(types.ServerError{Code: -1, Text: "the daemon has died"})
		c.Assert(err, Equals, nil)
	}))
	defer server.Close()

	cli := NewTestClient(server.URL, c)

	ep := types.Endpoint{
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

	err := cli.EndpointSave(ep)

	c.Assert(strings.Contains(err.Error(), "the daemon has died"), Equals, true)
}

func (s *CiliumNetClientSuite) TestEndpointLabelsGetOK(c *C) {
	ep := types.Endpoint{
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
	epLbls := types.Labels{
		"foo": types.NewLabel("foo", "bar", "cilium"),
	}
	ciliumLbls := types.Labels{
		"bar": types.NewLabel("bar", "foo", "cilium"),
	}
	allLabels := types.OpLabels{
		AllLabels:      ciliumLbls,
		EndpointLabels: epLbls,
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c.Assert(r.Method, Equals, "GET")
		c.Assert(r.URL.Path, Equals, "/endpoint/labels/4370") //0x1112
		w.WriteHeader(http.StatusOK)
		allLabels := types.OpLabels{
			AllLabels:      ciliumLbls,
			EndpointLabels: epLbls,
		}
		err := json.NewEncoder(w).Encode(allLabels)
		c.Assert(err, IsNil)
	}))
	defer server.Close()

	cli := NewTestClient(server.URL, c)

	lbls, err := cli.EndpointLabelsGet(ep.ID)

	c.Assert(allLabels, DeepEquals, *lbls)
	c.Assert(err, IsNil)
}

func (s *CiliumNetClientSuite) TestEndpointLabelsGetFail(c *C) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c.Assert(r.Method, Equals, "GET")
		c.Assert(r.URL.Path, Equals, "/endpoint/labels/4370") //0x1112
		w.WriteHeader(http.StatusNotFound)
		w.Header().Set("Content-Type", "application/json")
		err := json.NewEncoder(w).Encode(types.ServerError{Code: -1, Text: "the daemon has died"})
		c.Assert(err, Equals, nil)
	}))
	defer server.Close()

	cli := NewTestClient(server.URL, c)

	ep := types.Endpoint{
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

	lbls, err := cli.EndpointLabelsGet(ep.ID)
	c.Assert(lbls, IsNil)
	c.Assert(strings.Contains(err.Error(), "the daemon has died"), Equals, true)
}

func (s *CiliumNetClientSuite) TestEndpointLabelsUpdateOK(c *C) {
	ep := types.Endpoint{
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
	lbls := types.LabelOp{
		types.AddLabelsOp: types.Labels{
			"foo": types.NewLabel("foo", "bar", "cilium"),
		},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c.Assert(r.Method, Equals, "POST")
		c.Assert(r.URL.Path, Equals, "/endpoint/labels/4370") //0x1112
		var opLabels types.LabelOp
		err := json.NewDecoder(r.Body).Decode(&opLabels)
		c.Assert(err, IsNil)
		c.Assert(opLabels, DeepEquals, lbls)
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()

	cli := NewTestClient(server.URL, c)

	err := cli.EndpointLabelsUpdate(ep.ID, lbls)

	c.Assert(err, IsNil)
}

func (s *CiliumNetClientSuite) TestEndpointLabelsUpdateFail(c *C) {
	lbls := types.LabelOp{
		types.AddLabelsOp: types.Labels{
			"foo": types.NewLabel("foo", "bar", "cilium"),
		},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c.Assert(r.Method, Equals, "POST")
		c.Assert(r.URL.Path, Equals, "/endpoint/labels/4370") //0x1112
		var labelOp types.LabelOp
		err := json.NewDecoder(r.Body).Decode(&labelOp)
		c.Assert(err, IsNil)
		c.Assert(lbls, DeepEquals, labelOp)
		w.WriteHeader(http.StatusNotFound)
		w.Header().Set("Content-Type", "application/json")
		err = json.NewEncoder(w).Encode(types.ServerError{Code: -1, Text: "the daemon has died"})
		c.Assert(err, Equals, nil)
	}))
	defer server.Close()

	cli := NewTestClient(server.URL, c)

	ep := types.Endpoint{
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

	err := cli.EndpointLabelsUpdate(ep.ID, lbls)

	c.Assert(strings.Contains(err.Error(), "the daemon has died"), Equals, true)
}
