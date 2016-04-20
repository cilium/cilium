package types

import (
	"bytes"
	"net"
	"testing"

	. "github.com/noironetworks/cilium-net/Godeps/_workspace/src/gopkg.in/check.v1"
)

var (
	EpAddr = net.IP{0xbe, 0xef, 0xbe, 0xef, 0xbe, 0xef, 0xbe, 0xef, 0xaa, 0xaa, 0xaa, 0xaa, 0x11, 0x11, 0x11, 0x12}
)

// Hook up gocheck into the "go test" runner.
func Test(t *testing.T) { TestingT(t) }

type EndpointSuite struct{}

var _ = Suite(&EndpointSuite{})

func (s *EndpointSuite) TestEndpointID(c *C) {
	e := Endpoint{LXCIP: EpAddr}
	e.SetID()
	c.Assert(e.ID, Equals, "4370") //"0x1112"
	c.Assert(bytes.Compare(e.LXCIP, EpAddr) == 0, Equals, true)
}

func (s *EndpointSuite) TestGetFmtOpt(c *C) {
	e := Endpoint{
		Opts: EPOpts{
			"FOO": true,
			"BAR": false,
		},
	}
	c.Assert(e.GetFmtOpt("FOO"), Equals, "#define FOO")
	c.Assert(e.GetFmtOpt("BAR"), Equals, "#undef BAR")
	c.Assert(e.GetFmtOpt("BAZ"), Equals, "#undef BAZ")
}
