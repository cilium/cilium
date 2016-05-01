package client

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/noironetworks/cilium-net/common/types"

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
	cli, err := NewClient(urlStr, nil, transport, nil)
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
		fmt.Fprint(w, `Something went wrong`)
	}))
	defer server.Close()

	cli := NewTestClient(server.URL, c)

	res, err := cli.Ping()

	c.Assert(res, Equals, nilResponse)
	c.Assert(strings.HasSuffix(err.Error(), "Something went wrong"), Equals, true)
}
