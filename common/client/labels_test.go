package client

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"

	"github.com/noironetworks/cilium-net/common"
	"github.com/noironetworks/cilium-net/common/types"

	. "github.com/noironetworks/cilium-net/Godeps/_workspace/src/gopkg.in/check.v1"
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
		ID:       123,
		RefCount: 1,
		Labels:   lbls,
	}
)

func (s *CiliumNetClientSuite) TestPutLabelsOK(c *C) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c.Assert(r.Method, Equals, "POST")
		c.Assert(r.URL.Path, Equals, "/labels")
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

	secCtxLbls, _, err := cli.PutLabels(lbls)
	c.Assert(err, Equals, nil)
	c.Assert(*secCtxLbls, DeepEquals, seclbl)
}

func (s *CiliumNetClientSuite) TestPutLabelsFail(c *C) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c.Assert(r.Method, Equals, "POST")
		c.Assert(r.URL.Path, Equals, "/labels")
		w.WriteHeader(http.StatusInternalServerError)
		w.Header().Set("Content-Type", "application/json")
		err := json.NewEncoder(w).Encode(types.ServerError{-1, "the daemon has died"})
		c.Assert(err, Equals, nil)
	}))
	defer server.Close()

	cli := NewTestClient(server.URL, c)

	_, _, err := cli.PutLabels(lbls)
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
		c.Assert(r.URL.Path, Equals, "/labels/by-uuid/123")
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	cli := NewTestClient(server.URL, c)

	err := cli.DeleteLabelsByUUID(123)
	c.Assert(err, Equals, nil)
}

func (s *CiliumNetClientSuite) TestDeleteLabelsByUUIDFail(c *C) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c.Assert(r.Method, Equals, "DELETE")
		c.Assert(r.URL.Path, Equals, "/labels/by-uuid/123")
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	cli := NewTestClient(server.URL, c)

	err := cli.DeleteLabelsByUUID(123)
	c.Assert(err, Not(Equals), nil)
}

func (s *CiliumNetClientSuite) TestDeleteLabelsBySHA256OK(c *C) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c.Assert(r.Method, Equals, "DELETE")
		c.Assert(r.URL.Path, Equals, "/labels/by-sha256sum/a7c782feccd5cd9a94a524b1a49d1cd3ffacdb5591b157217e07ab32a821a504")
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	cli := NewTestClient(server.URL, c)

	err := cli.DeleteLabelsBySHA256("a7c782feccd5cd9a94a524b1a49d1cd3ffacdb5591b157217e07ab32a821a504")
	c.Assert(err, Equals, nil)
}

func (s *CiliumNetClientSuite) TestDeleteLabelsBySHA256Fail(c *C) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c.Assert(r.Method, Equals, "DELETE")
		c.Assert(r.URL.Path, Equals, "/labels/by-sha256sum/a7c782feccd5cd9a94a524b1a49d1cd3ffacdb5591b157217e07ab32a821a504")
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	cli := NewTestClient(server.URL, c)

	err := cli.DeleteLabelsBySHA256("a7c782feccd5cd9a94a524b1a49d1cd3ffacdb5591b157217e07ab32a821a504")
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

	maxID, err := cli.GetMaxID()
	c.Assert(err, Equals, nil)
	c.Assert(maxID, Equals, 123)
}

func (s *CiliumNetClientSuite) TestGetMaxIDFail(c *C) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c.Assert(r.Method, Equals, "GET")
		c.Assert(r.URL.Path, Equals, "/labels/status/maxUUID")
		w.WriteHeader(http.StatusInternalServerError)
		w.Header().Set("Content-Type", "application/json")
		err := json.NewEncoder(w).Encode(types.ServerError{-1, "the daemon has died"})
		c.Assert(err, Equals, nil)
	}))
	defer server.Close()

	cli := NewTestClient(server.URL, c)

	_, err := cli.GetMaxID()
	c.Assert(strings.Contains(err.Error(), "the daemon has died"), Equals, true)
}
