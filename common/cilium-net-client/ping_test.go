package cilium_net_client

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	. "github.com/noironetworks/cilium-net/Godeps/_workspace/src/gopkg.in/check.v1"
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
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c.Assert(r.Method, Equals, "GET")
		c.Assert(r.URL.Path, Equals, "/ping")
		w.WriteHeader(http.StatusOK)
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprint(w, `Pong`)
	}))
	defer server.Close()

	cli := NewTestClient(server.URL, c)

	res, err := cli.Ping()

	c.Assert(res, Equals, "Pong")
	c.Assert(err, Equals, nil)
}

func (s *CiliumNetClientSuite) TestPingFail(c *C) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c.Assert(r.Method, Equals, "GET")
		c.Assert(r.URL.Path, Equals, "/ping")
		w.WriteHeader(http.StatusRequestTimeout)
		fmt.Fprint(w, `Something went wrong`)
	}))
	defer server.Close()

	cli := NewTestClient(server.URL, c)

	res, err := cli.Ping()

	c.Assert(res, Equals, "")
	c.Assert(strings.HasSuffix(err.Error(), "Something went wrong"), Equals, true)
}
