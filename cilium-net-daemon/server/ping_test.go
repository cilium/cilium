package server

import (
	"errors"
	"net"
	"strings"
	"testing"

	cnc "github.com/noironetworks/cilium-net/common/client"

	. "gopkg.in/check.v1"
)

// Hook up gocheck into the "go test" runner.
func Test(t *testing.T) { TestingT(t) }

type DaemonSuite struct {
	d *TestDaemon
	s *Server
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

	s.s = &Server{l, r, "127.0.0.1"}
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
	s.d.OnPing = func() (string, error) {
		return "Pong", nil
	}

	res, err := s.c.Ping()
	c.Assert(res, Equals, "Pong")
	c.Assert(err, Equals, nil)
}

func (s *DaemonSuite) TestPingFail(c *C) {
	s.d.OnPing = func() (string, error) {
		return "Pong", errors.New("I'll fail")
	}

	res, err := s.c.Ping()
	c.Assert(res, Equals, "")
	c.Assert(strings.Contains(err.Error(), "I'll fail"), Equals, true)
}
