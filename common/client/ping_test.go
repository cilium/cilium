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
	"net/url"
	"strings"
	"testing"

	"github.com/cilium/cilium/common/types"

	. "gopkg.in/check.v1"
)

// Hook up gocheck into the "go test" runner.
func Test(t *testing.T) { TestingT(t) }

type CiliumNetClientSuite struct {
}

var _ = Suite(&CiliumNetClientSuite{})

func NewTestClient(urlStr string, c *C) *Client {
	transport := &http.Transport{
		Proxy: func(req *http.Request) (*url.URL, error) {
			return url.Parse(urlStr)
		},
	}
	cli, err := NewClient(urlStr, transport)
	if err != nil {
		c.Fatalf("Failed while creating new cilium-net test client: %+v", err)
	}
	return cli
}

func (s *CiliumNetClientSuite) TestPingOK(c *C) {
	resOut := types.PingResponse{NodeAddress: "foo"}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c.Assert(r.Method, Equals, "GET")
		c.Assert(r.URL.Path, Equals, "/ping")
		w.WriteHeader(http.StatusOK)
		w.Header().Set("Content-Type", "text/plain")
		err := json.NewEncoder(w).Encode(resOut)
		c.Assert(err, IsNil)
	}))
	defer server.Close()

	cli := NewTestClient(server.URL, c)

	res, err := cli.Ping()

	c.Assert(err, Equals, nil)
	c.Assert(*res, DeepEquals, resOut)
}

func (s *CiliumNetClientSuite) TestPingFail(c *C) {
	var nilResponse *types.PingResponse
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c.Assert(r.Method, Equals, "GET")
		c.Assert(r.URL.Path, Equals, "/ping")
		w.WriteHeader(http.StatusRequestTimeout)
		err := json.NewEncoder(w).Encode(types.ServerError{Code: -1, Text: "Something went wrong"})
		c.Assert(err, IsNil)
	}))
	defer server.Close()

	cli := NewTestClient(server.URL, c)

	res, err := cli.Ping()

	c.Assert(res, Equals, nilResponse)
	c.Assert(strings.HasSuffix(err.Error(), "Something went wrong"), Equals, true)
}
