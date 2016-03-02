package cilium_net_client

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"

	"github.com/noironetworks/cilium-net/common/types"

	. "github.com/noironetworks/cilium-net/Godeps/_workspace/src/gopkg.in/check.v1"
)

var (
	lbls = types.Labels{
		"foo":    "bar",
		"foo2":   "=bar2",
		"key":    "",
		"foo==":  "==",
		`foo\\=`: `\=`,
		`//=/`:   "",
		`%`:      `%ed`,
	}
)

func (s *CiliumNetClientSuite) TestGetLabelsIDOK(c *C) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c.Assert(r.Method, Equals, "POST")
		c.Assert(r.URL.Path, Equals, "/labels")
		d := json.NewDecoder(r.Body)
		var receivedLabels types.Labels
		err := d.Decode(&receivedLabels)
		c.Assert(err, Equals, nil)
		c.Assert(receivedLabels, DeepEquals, lbls)
		w.WriteHeader(http.StatusAccepted)
		w.Header().Set("Content-Type", "application/json")
		e := json.NewEncoder(w)
		err = e.Encode(types.LabelsResponse{ID: 123})
		c.Assert(err, Equals, nil)
	}))
	defer server.Close()

	cli := NewTestClient(server.URL, c)

	id, err := cli.GetLabelsID(lbls)
	c.Assert(err, Equals, nil)
	c.Assert(id, Equals, 123)
}

func (s *CiliumNetClientSuite) TestGetLabelsIDFail(c *C) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c.Assert(r.Method, Equals, "POST")
		c.Assert(r.URL.Path, Equals, "/labels")
		w.WriteHeader(http.StatusInternalServerError)
		w.Header().Set("Content-Type", "application/json")
		e := json.NewEncoder(w)
		err := e.Encode(types.ServerError{-1, "the daemon has died"})
		c.Assert(err, Equals, nil)
	}))
	defer server.Close()

	cli := NewTestClient(server.URL, c)

	_, err := cli.GetLabelsID(lbls)
	c.Assert(strings.Contains(err.Error(), "the daemon has died"), Equals, true)
}

func (s *CiliumNetClientSuite) TestGetLabelsOK(c *C) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c.Assert(r.Method, Equals, "GET")
		c.Assert(r.URL.Path, Equals, "/labels/by-uuid/123")
		w.WriteHeader(http.StatusOK)
		w.Header().Set("Content-Type", "application/json")
		err := json.NewEncoder(w).Encode(lbls)
		c.Assert(err, Equals, nil)
	}))
	defer server.Close()

	cli := NewTestClient(server.URL, c)

	receivedLabels, err := cli.GetLabels(123)
	c.Assert(err, Equals, nil)
	c.Assert(*receivedLabels, DeepEquals, lbls)
}

func (s *CiliumNetClientSuite) TestGetLabelsFail(c *C) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c.Assert(r.Method, Equals, "GET")
		c.Assert(r.URL.Path, Equals, "/labels/by-uuid/123")
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	cli := NewTestClient(server.URL, c)

	var wantLabels *types.Labels
	receivedLabels, err := cli.GetLabels(123)
	c.Assert(err, Equals, nil)
	c.Assert(receivedLabels, Equals, wantLabels)
}

func (s *CiliumNetClientSuite) TestGetMaxIDOK(c *C) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c.Assert(r.Method, Equals, "GET")
		c.Assert(r.URL.Path, Equals, "/labels/status/maxUUID")
		w.WriteHeader(http.StatusOK)
		w.Header().Set("Content-Type", "application/json")
		err := json.NewEncoder(w).Encode(types.LabelsResponse{ID: 123})
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
		e := json.NewEncoder(w)
		err := e.Encode(types.ServerError{-1, "the daemon has died"})
		c.Assert(err, Equals, nil)
	}))
	defer server.Close()

	cli := NewTestClient(server.URL, c)

	_, err := cli.GetMaxID()
	c.Assert(strings.Contains(err.Error(), "the daemon has died"), Equals, true)
}
