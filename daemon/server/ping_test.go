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
package server

import (
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	cnc "github.com/cilium/cilium/common/client"
	"github.com/cilium/cilium/common/types"

	. "gopkg.in/check.v1"
)

// Hook up gocheck into the "go test" runner.
func Test(t *testing.T) { TestingT(t) }

type DaemonSuite struct {
	d *TestDaemon
	s *server
	c *cnc.Client
}

var _ = Suite(&DaemonSuite{})

func (s *DaemonSuite) SetUpSuite(c *C) {
	time.Local = time.UTC
	s.d = NewTestDaemon()

	r := NewRouter(s.d)

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		c.Fatalf("Error while trying to listen: %+v", err)
	}

	s.s = &server{l, "127.0.0.1", r}
	go func() {
		if err := s.s.Start(); err != nil {
			c.Fatalf("Error while starting cilium-net test server: %s", err)
			s.s.Stop()
		}
	}()

	s.c, err = cnc.NewClient("http://"+s.s.listener.Addr().String(), nil)
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
