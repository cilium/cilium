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
	"net/http"
	"net/http/httptest"
	"strings"

	"github.com/cilium/cilium/common/types"
	"github.com/cilium/cilium/pkg/endpoint"

	. "gopkg.in/check.v1"
)

func (s *CiliumNetClientSuite) TestStatusOK(c *C) {
	resOut := endpoint.StatusResponse{Cilium: endpoint.NewStatusOK("Foo")}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c.Assert(r.Method, Equals, "GET")
		c.Assert(r.URL.Path, Equals, "/healthz")
		w.WriteHeader(http.StatusOK)
		err := json.NewEncoder(w).Encode(resOut)
		c.Assert(err, IsNil)
	}))
	defer server.Close()

	cli := NewTestClient(server.URL, c)

	res, err := cli.GlobalStatus()

	c.Assert(err, Equals, nil)
	c.Assert(*res, DeepEquals, resOut)
}

func (s *CiliumNetClientSuite) TestStatusFail(c *C) {
	var nilResponse *endpoint.StatusResponse
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c.Assert(r.Method, Equals, "GET")
		c.Assert(r.URL.Path, Equals, "/healthz")
		w.WriteHeader(http.StatusRequestTimeout)
		err := json.NewEncoder(w).Encode(types.ServerError{Code: -1, Text: "Something went wrong"})
		c.Assert(err, IsNil)
	}))
	defer server.Close()

	cli := NewTestClient(server.URL, c)

	res, err := cli.GlobalStatus()

	c.Assert(res, Equals, nilResponse)
	c.Assert(strings.HasSuffix(err.Error(), "Something went wrong"), Equals, true)
}
