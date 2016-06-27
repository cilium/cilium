package server

import (
	"errors"
	"net"
	"strings"
	"testing"

	cnc "github.com/noironetworks/cilium-net/common/client"
	"github.com/noironetworks/cilium-net/common/types"

	. "gopkg.in/check.v1"
)

// Hook up gocheck into the "go test" runner.
func Test(t *testing.T) { TestingT(t) }

type DaemonSuite struct {
	d *TestDaemon
	s *serverBackend
	c *cnc.Client
}

var _ = Suite(&DaemonSuite{})

func (s *DaemonSuite) SetUpSuite(c *C) {
	s.d = NewTestDaemon()

	r := NewRouter(s.d)

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		c.Fatalf("Error while trying to listen: %+v", err)
	}

	s.s = &serverBackend{serverCommon{l, "127.0.0.1"}, r}
	go func() {
		if err := s.s.Start(); err != nil {
			c.Fatalf("Error while starting cilium-net test server: %s", err)
			s.s.Stop()
		}
	}()

	s.c, err = cnc.NewClient("http://"+s.s.listener.Addr().String(), nil, nil, nil)
	if err != nil {
		c.Fatalf("Error while trying to listen: %+v", err)
	}
}

func (s *DaemonSuite) TearDownSuite(c *C) {
	s.s.Stop()
}

func (s *DaemonSuite) TestPingOK(c *C) {
	s.d.OnPing = func() (*types.PingResponse, error) {
		return &types.PingResponse{NodeAddress: "foo"}, nil
	}

	resp, err := s.c.Ping()
	c.Assert(resp.NodeAddress, Equals, "foo")
	c.Assert(err, Equals, nil)
}

func (s *DaemonSuite) TestPingFail(c *C) {
	var nilResponse *types.PingResponse
	s.d.OnPing = func() (*types.PingResponse, error) {
		return nil, errors.New("I'll fail")
	}

	res, err := s.c.Ping()
	c.Assert(res, Equals, nilResponse)
	c.Assert(strings.Contains(err.Error(), "I'll fail"), Equals, true)
}
