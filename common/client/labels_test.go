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
	"time"

	"github.com/cilium/cilium/common"
	"github.com/cilium/cilium/common/types"

	. "gopkg.in/check.v1"
)

var (
	lbls = types.Labels{
		"foo":    types.NewLabel("foo", "bar", common.CiliumLabelSource),
		"foo2":   types.NewLabel("foo2", "=bar2", common.CiliumLabelSource),
		"key":    types.NewLabel("key", "", common.CiliumLabelSource),
		"foo==":  types.NewLabel("foo==", "==", common.CiliumLabelSource),
		`foo\\=`: types.NewLabel(`foo\\=`, `\=`, common.CiliumLabelSource),
		`//=/`:   types.NewLabel(`//=/`, "", common.CiliumLabelSource),
		`%`:      types.NewLabel(`%`, `%ed`, common.CiliumLabelSource),
	}
	seclbl = types.SecCtxLabel{
		ID: 123,
		Containers: map[string]time.Time{
			"cc08ff400e355f736dce1c291a6a4007ab9f2d56d42e1f3630ba87b861d45307": time.Now(),
		},
		Labels: lbls,
	}
)

func (s *CiliumNetClientSuite) TestPutLabelsOK(c *C) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c.Assert(r.Method, Equals, "POST")
		c.Assert(r.URL.Path, Equals, "/labels/cc08ff400e355f736dce1c291a6a4007ab9f2d56d42e1f3630ba87b861d45307")
		var receivedLabels types.Labels
		err := json.NewDecoder(r.Body).Decode(&receivedLabels)
		c.Assert(err, Equals, nil)
		c.Assert(receivedLabels, DeepEquals, lbls)
		w.WriteHeader(http.StatusAccepted)
		w.Header().Set("Content-Type", "application/json")
		err = json.NewEncoder(w).Encode(seclbl)
		c.Assert(err, Equals, nil)
	}))
	defer server.Close()

	cli := NewTestClient(server.URL, c)

	secCtxLbls, _, err := cli.PutLabels(lbls, "cc08ff400e355f736dce1c291a6a4007ab9f2d56d42e1f3630ba87b861d45307")
	c.Assert(err, Equals, nil)
	c.Assert(*secCtxLbls, DeepEquals, seclbl)
}

func (s *CiliumNetClientSuite) TestPutLabelsFail(c *C) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c.Assert(r.Method, Equals, "POST")
		c.Assert(r.URL.Path, Equals, "/labels/cc08ff400e355f736dce1c291a6a4007ab9f2d56d42e1f3630ba87b861d45307")
		w.WriteHeader(http.StatusInternalServerError)
		w.Header().Set("Content-Type", "application/json")
		err := json.NewEncoder(w).Encode(types.ServerError{Code: -1, Text: "the daemon has died"})
		c.Assert(err, Equals, nil)
	}))
	defer server.Close()

	cli := NewTestClient(server.URL, c)

	_, _, err := cli.PutLabels(lbls, "cc08ff400e355f736dce1c291a6a4007ab9f2d56d42e1f3630ba87b861d45307")
	c.Assert(strings.Contains(err.Error(), "the daemon has died"), Equals, true)
}

func (s *CiliumNetClientSuite) TestGetLabelsOK(c *C) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c.Assert(r.Method, Equals, "GET")
		c.Assert(r.URL.Path, Equals, "/labels/by-uuid/123")
		w.WriteHeader(http.StatusOK)
		w.Header().Set("Content-Type", "application/json")
		err := json.NewEncoder(w).Encode(seclbl)
		c.Assert(err, Equals, nil)
	}))
	defer server.Close()

	cli := NewTestClient(server.URL, c)

	secCtxLbls, err := cli.GetLabels(123)
	c.Assert(err, Equals, nil)
	c.Assert(*secCtxLbls, DeepEquals, seclbl)
}

func (s *CiliumNetClientSuite) TestGetLabelsFail(c *C) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c.Assert(r.Method, Equals, "GET")
		c.Assert(r.URL.Path, Equals, "/labels/by-uuid/123")
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	cli := NewTestClient(server.URL, c)

	var wantLabels *types.SecCtxLabel
	receivedLabels, err := cli.GetLabels(123)
	c.Assert(err, Equals, nil)
	c.Assert(receivedLabels, Equals, wantLabels)
}

func (s *CiliumNetClientSuite) TestGetLabelsBySHA256SOK(c *C) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c.Assert(r.Method, Equals, "GET")
		c.Assert(r.URL.Path, Equals, "/labels/by-sha256sum/a7c782feccd5cd9a94a524b1a49d1cd3ffacdb5591b157217e07ab32a821a504")
		w.WriteHeader(http.StatusOK)
		w.Header().Set("Content-Type", "application/json")
		err := json.NewEncoder(w).Encode(seclbl)
		c.Assert(err, Equals, nil)
	}))
	defer server.Close()

	cli := NewTestClient(server.URL, c)

	secCtxLbls, err := cli.GetLabelsBySHA256("a7c782feccd5cd9a94a524b1a49d1cd3ffacdb5591b157217e07ab32a821a504")
	c.Assert(err, Equals, nil)
	c.Assert(*secCtxLbls, DeepEquals, seclbl)
}

func (s *CiliumNetClientSuite) TestGetLabelsBySHA256Fail(c *C) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c.Assert(r.Method, Equals, "GET")
		c.Assert(r.URL.Path, Equals, "/labels/by-sha256sum/a7c782feccd5cd9a94a524b1a49d1cd3ffacdb5591b157217e07ab32a821a504")
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	cli := NewTestClient(server.URL, c)

	var wantLabels *types.SecCtxLabel
	receivedLabels, err := cli.GetLabelsBySHA256("a7c782feccd5cd9a94a524b1a49d1cd3ffacdb5591b157217e07ab32a821a504")
	c.Assert(err, Equals, nil)
	c.Assert(receivedLabels, Equals, wantLabels)
}

func (s *CiliumNetClientSuite) TestDeleteLabelsByUUIDOK(c *C) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c.Assert(r.Method, Equals, "DELETE")
		c.Assert(r.URL.Path, Equals, "/labels/by-uuid/123/cc08ff400e355f736dce1c291a6a4007ab9f2d56d42e1f3630ba87b861d45307")
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	cli := NewTestClient(server.URL, c)

	err := cli.DeleteLabelsByUUID(123, "cc08ff400e355f736dce1c291a6a4007ab9f2d56d42e1f3630ba87b861d45307")
	c.Assert(err, Equals, nil)
}

func (s *CiliumNetClientSuite) TestDeleteLabelsByUUIDFail(c *C) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c.Assert(r.Method, Equals, "DELETE")
		c.Assert(r.URL.Path, Equals, "/labels/by-uuid/123/cc08ff400e355f736dce1c291a6a4007ab9f2d56d42e1f3630ba87b861d45307")
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	cli := NewTestClient(server.URL, c)

	err := cli.DeleteLabelsByUUID(123, "cc08ff400e355f736dce1c291a6a4007ab9f2d56d42e1f3630ba87b861d45307")
	c.Assert(err, Not(Equals), nil)
}

func (s *CiliumNetClientSuite) TestDeleteLabelsBySHA256OK(c *C) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c.Assert(r.Method, Equals, "DELETE")
		c.Assert(r.URL.Path, Equals, "/labels/by-sha256sum/a7c782feccd5cd9a94a524b1a49d1cd3ffacdb5591b157217e07ab32a821a504"+
			"/cc08ff400e355f736dce1c291a6a4007ab9f2d56d42e1f3630ba87b861d45307")
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	cli := NewTestClient(server.URL, c)

	err := cli.DeleteLabelsBySHA256("a7c782feccd5cd9a94a524b1a49d1cd3ffacdb5591b157217e07ab32a821a504", "cc08ff400e355f736dce1c291a6a4007ab9f2d56d42e1f3630ba87b861d45307")
	c.Assert(err, Equals, nil)
}

func (s *CiliumNetClientSuite) TestDeleteLabelsBySHA256Fail(c *C) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c.Assert(r.Method, Equals, "DELETE")
		c.Assert(r.URL.Path, Equals, "/labels/by-sha256sum/a7c782feccd5cd9a94a524b1a49d1cd3ffacdb5591b157217e07ab32a821a504"+
			"/cc08ff400e355f736dce1c291a6a4007ab9f2d56d42e1f3630ba87b861d45307")
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	cli := NewTestClient(server.URL, c)

	err := cli.DeleteLabelsBySHA256("a7c782feccd5cd9a94a524b1a49d1cd3ffacdb5591b157217e07ab32a821a504", "cc08ff400e355f736dce1c291a6a4007ab9f2d56d42e1f3630ba87b861d45307")
	c.Assert(err, Not(Equals), nil)
}

func (s *CiliumNetClientSuite) TestGetMaxIDOK(c *C) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c.Assert(r.Method, Equals, "GET")
		c.Assert(r.URL.Path, Equals, "/labels/status/maxUUID")
		w.WriteHeader(http.StatusOK)
		w.Header().Set("Content-Type", "application/json")
		err := json.NewEncoder(w).Encode(123)
		c.Assert(err, Equals, nil)
	}))
	defer server.Close()

	cli := NewTestClient(server.URL, c)

	maxID, err := cli.GetMaxLabelID()
	c.Assert(err, Equals, nil)
	c.Assert(maxID, Equals, uint32(123))
}

func (s *CiliumNetClientSuite) TestGetMaxIDFail(c *C) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c.Assert(r.Method, Equals, "GET")
		c.Assert(r.URL.Path, Equals, "/labels/status/maxUUID")
		w.WriteHeader(http.StatusInternalServerError)
		w.Header().Set("Content-Type", "application/json")
		err := json.NewEncoder(w).Encode(types.ServerError{Code: -1, Text: "the daemon has died"})
		c.Assert(err, Equals, nil)
	}))
	defer server.Close()

	cli := NewTestClient(server.URL, c)

	_, err := cli.GetMaxLabelID()
	c.Assert(strings.Contains(err.Error(), "the daemon has died"), Equals, true)
}
