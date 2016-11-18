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

	"github.com/cilium/cilium/common/types"

	. "gopkg.in/check.v1"
	"strconv"
)

var (
	randomAddr1 = net.ParseIP("beef:beef:beef:beef:aaaa:aaaa:1111:0:1")
	randomAddr2 = net.ParseIP("beef:beef:beef:beef:aaaa:aaaa:1111:0:2")
	revNat1     = types.L3n4Addr{
		IP: randomAddr1,
		L4Addr: types.L4Addr{
			Protocol: types.TCP,
			Port:     1984,
		},
	}
	revNat2 = types.L3n4Addr{
		IP: randomAddr2,
		L4Addr: types.L4Addr{
			Protocol: types.TCP,
			Port:     1911,
		},
	}
)

func (s *CiliumNetClientSuite) TestSVCAddOK(c *C) {

	fe, err := types.NewL3n4AddrID(types.TCP, randomAddr1, 1984, 2016)
	c.Assert(err, IsNil)
	wantLBSVC := types.LBSVC{
		FE: *fe,
		BES: []types.L3n4Addr{
			revNat1,
			revNat2,
		},
	}
	addRevNAT := true

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c.Assert(r.Method, Equals, "POST")
		c.Assert(r.URL.Path, Equals, "/lb/service")
		var receivedLBSVC types.LBSVC
		err := json.NewDecoder(r.Body).Decode(&receivedLBSVC)
		c.Assert(err, Equals, nil)
		c.Assert(receivedLBSVC, DeepEquals, wantLBSVC)
		w.WriteHeader(http.StatusCreated)
	}))
	defer server.Close()

	cli := NewTestClient(server.URL, c)

	err = cli.SVCAdd(wantLBSVC.FE, wantLBSVC.BES, addRevNAT)

	c.Assert(err, Equals, nil)
}

func (s *CiliumNetClientSuite) TestSVCAddFail(c *C) {

	fe, err := types.NewL3n4AddrID(types.TCP, randomAddr1, 1984, 2016)
	c.Assert(err, IsNil)
	wantLBSVC := types.LBSVC{
		FE: *fe,
		BES: []types.L3n4Addr{
			revNat1,
			revNat2,
		},
	}
	addRevNAT := true

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c.Assert(r.Method, Equals, "POST")
		c.Assert(r.URL.Path, Equals, "/lb/service")
		var receivedLBSVC types.LBSVC
		err := json.NewDecoder(r.Body).Decode(&receivedLBSVC)
		c.Assert(err, Equals, nil)
		c.Assert(receivedLBSVC, DeepEquals, wantLBSVC)
		w.WriteHeader(http.StatusInternalServerError)
		w.Header().Set("Content-Type", "application/json")
		e := json.NewEncoder(w)
		err = e.Encode(types.ServerError{Code: -1, Text: "daemon didn't complete your request"})
		c.Assert(err, Equals, nil)
	}))
	defer server.Close()

	cli := NewTestClient(server.URL, c)

	err = cli.SVCAdd(wantLBSVC.FE, wantLBSVC.BES, addRevNAT)

	c.Assert(strings.Contains(err.Error(), "daemon didn't complete your request"), Equals, true)
}

func (s *CiliumNetClientSuite) TestSVCDeleteOK(c *C) {
	fe, err := types.NewL3n4Addr(types.TCP, randomAddr1, 1984)
	c.Assert(err, IsNil)
	feSHA256Sum, err := fe.SHA256Sum()
	c.Assert(err, IsNil)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c.Assert(r.Method, Equals, "DELETE")
		c.Assert(r.URL.Path, Equals, "/lb/service/"+feSHA256Sum)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	cli := NewTestClient(server.URL, c)

	err = cli.SVCDelete(*fe)

	c.Assert(err, Equals, nil)
}

func (s *CiliumNetClientSuite) TestSVCDeleteFail(c *C) {
	fe, err := types.NewL3n4Addr(types.TCP, randomAddr1, 1984)
	c.Assert(err, IsNil)
	feSHA256Sum, err := fe.SHA256Sum()
	c.Assert(err, IsNil)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c.Assert(r.Method, Equals, "DELETE")
		c.Assert(r.URL.Path, Equals, "/lb/service/"+feSHA256Sum)
		w.WriteHeader(http.StatusInternalServerError)
		w.Header().Set("Content-Type", "application/json")
		e := json.NewEncoder(w)
		err := e.Encode(types.ServerError{Code: -1, Text: "daemon didn't complete your request"})
		c.Assert(err, Equals, nil)
	}))
	defer server.Close()

	cli := NewTestClient(server.URL, c)

	err = cli.SVCDelete(*fe)

	c.Assert(strings.Contains(err.Error(), "daemon didn't complete your request"), Equals, true)
}

func (s *CiliumNetClientSuite) TestSVCDeleteAllOK(c *C) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c.Assert(r.Method, Equals, "DELETE")
		c.Assert(r.URL.Path, Equals, "/lb/services")
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	cli := NewTestClient(server.URL, c)

	err := cli.SVCDeleteAll()

	c.Assert(err, Equals, nil)
}

func (s *CiliumNetClientSuite) TestSVCDeleteAllFail(c *C) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c.Assert(r.Method, Equals, "DELETE")
		c.Assert(r.URL.Path, Equals, "/lb/services")
		w.WriteHeader(http.StatusInternalServerError)
		w.Header().Set("Content-Type", "application/json")
		e := json.NewEncoder(w)
		err := e.Encode(types.ServerError{Code: -1, Text: "daemon didn't complete your request"})
		c.Assert(err, Equals, nil)
	}))
	defer server.Close()

	cli := NewTestClient(server.URL, c)

	err := cli.SVCDeleteAll()

	c.Assert(strings.Contains(err.Error(), "daemon didn't complete your request"), Equals, true)
}

func (s *CiliumNetClientSuite) TestSVCGetOK(c *C) {
	fe, err := types.NewL3n4AddrID(types.TCP, randomAddr1, 1984, 2016)
	c.Assert(err, IsNil)
	wantLBSVC := types.LBSVC{
		FE: *fe,
		BES: []types.L3n4Addr{
			revNat1,
			revNat2,
		},
	}
	feSHA256Sum, err := fe.SHA256Sum()
	c.Assert(err, IsNil)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c.Assert(r.Method, Equals, "GET")
		c.Assert(r.URL.Path, Equals, "/lb/service/"+feSHA256Sum)
		w.WriteHeader(http.StatusOK)
		err := json.NewEncoder(w).Encode(wantLBSVC)
		c.Assert(err, Equals, nil)
	}))
	defer server.Close()

	cli := NewTestClient(server.URL, c)

	lbSvcReceived, err := cli.SVCGet(fe.L3n4Addr)

	c.Assert(err, IsNil)
	c.Assert(*lbSvcReceived, DeepEquals, wantLBSVC)
}

func (s *CiliumNetClientSuite) TestSVCGetFail(c *C) {
	fe, err := types.NewL3n4AddrID(types.TCP, randomAddr1, 1984, 2016)
	c.Assert(err, IsNil)
	feSHA256Sum, err := fe.SHA256Sum()
	c.Assert(err, IsNil)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c.Assert(r.Method, Equals, "GET")
		c.Assert(r.URL.Path, Equals, "/lb/service/"+feSHA256Sum)
		w.WriteHeader(http.StatusInternalServerError)
		w.Header().Set("Content-Type", "application/json")
		e := json.NewEncoder(w)
		err := e.Encode(types.ServerError{Code: -1, Text: "daemon didn't complete your request"})
		c.Assert(err, Equals, nil)
	}))
	defer server.Close()

	cli := NewTestClient(server.URL, c)

	lbSvcReceived, err := cli.SVCGet(fe.L3n4Addr)

	c.Assert(strings.Contains(err.Error(), "daemon didn't complete your request"), Equals, true)
	var nilFe *types.LBSVC
	c.Assert(lbSvcReceived, DeepEquals, nilFe)
}

func (s *CiliumNetClientSuite) TestSVCDumpOK(c *C) {
	fe, err := types.NewL3n4AddrID(types.TCP, randomAddr1, 1984, 2016)
	c.Assert(err, IsNil)
	wantLBSVC := []types.LBSVC{
		{
			FE: *fe,
			BES: []types.L3n4Addr{
				revNat1,
				revNat2,
			},
		},
		{
			FE: *fe,
			BES: []types.L3n4Addr{
				revNat1,
				revNat2,
			},
		},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c.Assert(r.Method, Equals, "GET")
		c.Assert(r.URL.Path, Equals, "/lb/services")
		w.WriteHeader(http.StatusOK)
		err := json.NewEncoder(w).Encode(wantLBSVC)
		c.Assert(err, Equals, nil)
	}))
	defer server.Close()

	cli := NewTestClient(server.URL, c)

	lbSVCReceived, err := cli.SVCDump()

	c.Assert(err, IsNil)
	c.Assert(lbSVCReceived, DeepEquals, wantLBSVC)
}

func (s *CiliumNetClientSuite) TestSVCDumpFail(c *C) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c.Assert(r.Method, Equals, "GET")
		c.Assert(r.URL.Path, Equals, "/lb/services")
		w.WriteHeader(http.StatusInternalServerError)
		w.Header().Set("Content-Type", "application/json")
		e := json.NewEncoder(w)
		err := e.Encode(types.ServerError{Code: -1, Text: "daemon didn't complete your request"})
		c.Assert(err, Equals, nil)
	}))
	defer server.Close()

	cli := NewTestClient(server.URL, c)

	lbSVCReceived, err := cli.SVCDump()

	c.Assert(strings.Contains(err.Error(), "daemon didn't complete your request"), Equals, true)
	var nilFe []types.LBSVC
	c.Assert(lbSVCReceived, DeepEquals, nilFe)
}

func (s *CiliumNetClientSuite) TestRevNATAddOK(c *C) {
	wantRevNATID := types.L3n4AddrID{
		ID:       2016,
		L3n4Addr: revNat1,
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c.Assert(r.Method, Equals, "POST")
		c.Assert(r.URL.Path, Equals, "/lb/revnat")
		var receivedRevNATID types.L3n4AddrID
		err := json.NewDecoder(r.Body).Decode(&receivedRevNATID)
		c.Assert(err, Equals, nil)
		c.Assert(receivedRevNATID, DeepEquals, wantRevNATID)
		w.WriteHeader(http.StatusCreated)
	}))
	defer server.Close()

	cli := NewTestClient(server.URL, c)

	err := cli.RevNATAdd(wantRevNATID.ID, wantRevNATID.L3n4Addr)
	c.Assert(err, Equals, nil)
}

func (s *CiliumNetClientSuite) TestRevNATAddFail(c *C) {
	wantRevNATID := types.L3n4AddrID{
		ID:       2016,
		L3n4Addr: revNat1,
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c.Assert(r.Method, Equals, "POST")
		c.Assert(r.URL.Path, Equals, "/lb/revnat")
		var receivedRevNATID types.L3n4AddrID
		err := json.NewDecoder(r.Body).Decode(&receivedRevNATID)
		c.Assert(err, Equals, nil)
		c.Assert(receivedRevNATID, DeepEquals, wantRevNATID)
		w.WriteHeader(http.StatusInternalServerError)
		w.Header().Set("Content-Type", "application/json")
		e := json.NewEncoder(w)
		err = e.Encode(types.ServerError{Code: -1, Text: "daemon didn't complete your request"})
		c.Assert(err, Equals, nil)
	}))
	defer server.Close()

	cli := NewTestClient(server.URL, c)

	err := cli.RevNATAdd(wantRevNATID.ID, wantRevNATID.L3n4Addr)

	c.Assert(strings.Contains(err.Error(), "daemon didn't complete your request"), Equals, true)
}

func (s *CiliumNetClientSuite) TestRevNATDeleteOK(c *C) {
	id := types.ServiceID(2016)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c.Assert(r.Method, Equals, "DELETE")
		c.Assert(r.URL.Path, Equals, "/lb/revnat/"+strconv.FormatUint(uint64(id), 10))
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	cli := NewTestClient(server.URL, c)

	err := cli.RevNATDelete(id)
	c.Assert(err, Equals, nil)
}

func (s *CiliumNetClientSuite) TestRevNATDeleteFail(c *C) {
	id := types.ServiceID(2016)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c.Assert(r.Method, Equals, "DELETE")
		c.Assert(r.URL.Path, Equals, "/lb/revnat/"+strconv.FormatUint(uint64(id), 10))
		w.WriteHeader(http.StatusInternalServerError)
		w.Header().Set("Content-Type", "application/json")
		e := json.NewEncoder(w)
		err := e.Encode(types.ServerError{Code: -1, Text: "daemon didn't complete your request"})
		c.Assert(err, Equals, nil)
	}))
	defer server.Close()

	cli := NewTestClient(server.URL, c)

	err := cli.RevNATDelete(id)
	c.Assert(strings.Contains(err.Error(), "daemon didn't complete your request"), Equals, true)
}

func (s *CiliumNetClientSuite) TestRevNATDeleteAllOK(c *C) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c.Assert(r.Method, Equals, "DELETE")
		c.Assert(r.URL.Path, Equals, "/lb/revnats")
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	cli := NewTestClient(server.URL, c)

	err := cli.RevNATDeleteAll()
	c.Assert(err, Equals, nil)
}

func (s *CiliumNetClientSuite) TestRevNATDeleteAllFail(c *C) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c.Assert(r.Method, Equals, "DELETE")
		c.Assert(r.URL.Path, Equals, "/lb/revnats")
		w.WriteHeader(http.StatusInternalServerError)
		w.Header().Set("Content-Type", "application/json")
		e := json.NewEncoder(w)
		err := e.Encode(types.ServerError{Code: -1, Text: "daemon didn't complete your request"})
		c.Assert(err, Equals, nil)
	}))
	defer server.Close()

	cli := NewTestClient(server.URL, c)

	err := cli.RevNATDeleteAll()
	c.Assert(strings.Contains(err.Error(), "daemon didn't complete your request"), Equals, true)
}

func (s *CiliumNetClientSuite) TestRevNATGetOK(c *C) {
	wantRevNATID := types.L3n4AddrID{
		ID:       2016,
		L3n4Addr: revNat1,
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c.Assert(r.Method, Equals, "GET")
		c.Assert(r.URL.Path, Equals, "/lb/revnat/"+strconv.FormatUint(uint64(wantRevNATID.ID), 10))
		w.WriteHeader(http.StatusOK)
		err := json.NewEncoder(w).Encode(wantRevNATID.L3n4Addr)
		c.Assert(err, Equals, nil)
	}))
	defer server.Close()

	cli := NewTestClient(server.URL, c)

	revNATReceived, err := cli.RevNATGet(wantRevNATID.ID)

	c.Assert(err, IsNil)
	c.Assert(*revNATReceived, DeepEquals, wantRevNATID.L3n4Addr)
}

func (s *CiliumNetClientSuite) TestRevNATGetFail(c *C) {
	wantRevNATID := types.L3n4AddrID{
		ID:       2016,
		L3n4Addr: revNat1,
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c.Assert(r.Method, Equals, "GET")
		c.Assert(r.URL.Path, Equals, "/lb/revnat/"+strconv.FormatUint(uint64(wantRevNATID.ID), 10))
		w.WriteHeader(http.StatusInternalServerError)
		w.Header().Set("Content-Type", "application/json")
		e := json.NewEncoder(w)
		err := e.Encode(types.ServerError{Code: -1, Text: "daemon didn't complete your request"})
		c.Assert(err, Equals, nil)
	}))
	defer server.Close()

	cli := NewTestClient(server.URL, c)

	revNATReceived, err := cli.RevNATGet(wantRevNATID.ID)

	c.Assert(strings.Contains(err.Error(), "daemon didn't complete your request"), Equals, true)
	var nilFe *types.L3n4Addr
	c.Assert(revNATReceived, Equals, nilFe)
}

func (s *CiliumNetClientSuite) TestRevNATDumpOK(c *C) {
	wantRevNATs := []types.L3n4AddrID{
		{
			ID:       1984,
			L3n4Addr: revNat1,
		},
		{
			ID:       1911,
			L3n4Addr: revNat2,
		},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c.Assert(r.Method, Equals, "GET")
		c.Assert(r.URL.Path, Equals, "/lb/revnats")
		w.WriteHeader(http.StatusOK)
		err := json.NewEncoder(w).Encode(wantRevNATs)
		c.Assert(err, Equals, nil)
	}))
	defer server.Close()

	cli := NewTestClient(server.URL, c)

	revNATsReceived, err := cli.RevNATDump()

	c.Assert(err, IsNil)
	c.Assert(revNATsReceived, DeepEquals, wantRevNATs)
}

func (s *CiliumNetClientSuite) TestRevNATDumpFail(c *C) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c.Assert(r.Method, Equals, "GET")
		c.Assert(r.URL.Path, Equals, "/lb/revnats")
		w.WriteHeader(http.StatusInternalServerError)
		w.Header().Set("Content-Type", "application/json")
		e := json.NewEncoder(w)
		err := e.Encode(types.ServerError{Code: -1, Text: "daemon didn't complete your request"})
		c.Assert(err, Equals, nil)
	}))
	defer server.Close()

	cli := NewTestClient(server.URL, c)

	lbSVCReceived, err := cli.RevNATDump()

	c.Assert(strings.Contains(err.Error(), "daemon didn't complete your request"), Equals, true)
	var nilRevNATDump []types.L3n4AddrID
	c.Assert(lbSVCReceived, DeepEquals, nilRevNATDump)
}

func (s *CiliumNetClientSuite) TestSyncLBMapOK(c *C) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c.Assert(r.Method, Equals, "POST")
		c.Assert(r.URL.Path, Equals, "/lb/synclbmap")
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	cli := NewTestClient(server.URL, c)

	err := cli.SyncLBMap()
	c.Assert(err, IsNil)
}

func (s *CiliumNetClientSuite) TestSyncLBMapFail(c *C) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c.Assert(r.Method, Equals, "POST")
		c.Assert(r.URL.Path, Equals, "/lb/synclbmap")
		w.WriteHeader(http.StatusInternalServerError)
		w.Header().Set("Content-Type", "application/json")
		err := json.NewEncoder(w).Encode(types.ServerError{Code: -1, Text: "daemon didn't complete your request"})
		c.Assert(err, Equals, nil)
	}))
	defer server.Close()

	cli := NewTestClient(server.URL, c)

	err := cli.SyncLBMap()

	c.Assert(strings.Contains(err.Error(), "daemon didn't complete your request"), Equals, true)
}
