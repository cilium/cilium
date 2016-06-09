package common

import (
	"errors"
	"net"

	. "gopkg.in/check.v1"
)

var _ = Suite(&CommonSuite{})

func (s *CommonSuite) TestGoArray2C(c *C) {
	c.Assert(goArray2C([]byte{0, 0x01, 0x02, 0x03}), Equals, "{ 0x0, 0x1, 0x2, 0x3 }")
	c.Assert(goArray2C([]byte{0, 0xFF, 0xFF, 0xFF}), Equals, "{ 0x0, 0xff, 0xff, 0xff }")
	c.Assert(goArray2C([]byte{0xa, 0xbc, 0xde, 0xf1}), Equals, "{ 0xa, 0xbc, 0xde, 0xf1 }")
	c.Assert(goArray2C([]byte{0}), Equals, "{ 0x0 }")
	c.Assert(goArray2C([]byte{}), Equals, "{  }")
}

func (s *CommonSuite) TestFmtDefineAddress(c *C) {
	c.Assert(FmtDefineAddress("foo", []byte{1, 2, 3}), Equals, "#define foo { .addr = { 0x1, 0x2, 0x3 } }\n")
	c.Assert(FmtDefineAddress("foo", []byte{}), Equals, "#define foo { .addr = {  } }\n")
}

func (s *CommonSuite) TestFmtDefineArray(c *C) {
	c.Assert(FmtDefineArray("foo", []byte{1, 2, 3}), Equals, "#define foo { 0x1, 0x2, 0x3 }\n")
	c.Assert(FmtDefineArray("foo", []byte{}), Equals, "#define foo {  }\n")
}

func (s *CommonSuite) TestFmtV6Prefix(c *C) {
	c.Assert(fmtV6Prefix("beef::", []byte{}), Equals, "<nil>")
	c.Assert(fmtV6Prefix("beef::", []byte{1, 2, 3, 4}), Equals, "beef::0102:0304:0")
}

func (s *CommonSuite) TestSwab16(c *C) {
	c.Assert(Swab16(0xAABB), Equals, uint16(0xBBAA),
		Commentf("Swab16 failed: Swab16(0xAABB) != 0xBBAA"))
}

func (s *CommonSuite) TestSwab32(c *C) {
	c.Assert(Swab32(0xAABBCCDD), Equals, uint32(0xDDCCBBAA),
		Commentf("Swab32 failed: Swab16(0xAABBCCDD) != 0xDDCCBBAA"))
}

func (s *CommonSuite) TestFmtV4Range(c *C) {
	ip := net.ParseIP("1.2.3.4")

	r, err := fmtV4Range(&ip)
	c.Assert(r, Equals, "10.4.0.0/16")
	c.Assert(err, Equals, nil)
}

func (s *CommonSuite) TestParseHost(c *C) {
	var emptyPtr *net.TCPAddr
	tests := []struct {
		test string
		net  string
		want *net.TCPAddr
		err  error
	}{
		{
			"tcp://1.1.1.1:8081",
			"tcp",
			&net.TCPAddr{
				net.ParseIP("1.1.1.1"),
				8081,
				"",
			},
			nil,
		},
		{
			"tcp://0.0.0.0:8081",
			"tcp",
			&net.TCPAddr{
				net.ParseIP("0.0.0.0"),
				8081,
				"",
			},
			nil,
		},
		{
			"tcp://1.1.1.1:",
			"",
			emptyPtr,
			errors.New("invalid endpoint"),
		},
		{
			"tcp6://[::1]:8081",
			"tcp6",
			&net.TCPAddr{
				net.ParseIP("::1"),
				8081,
				"",
			},
			nil,
		},
		{
			"tcp6://[::1%eth0]:8081",
			"tcp6",
			&net.TCPAddr{
				net.ParseIP("::1"),
				8081,
				"eth0",
			},
			nil,
		},
	}
	for _, tt := range tests {
		netProto, tcpAddr, err := ParseHost(tt.test)
		c.Assert(err, DeepEquals, tt.err, Commentf("Test %s", tt.test))
		c.Assert(tcpAddr, DeepEquals, tt.want)
		c.Assert(netProto, Equals, tt.net)
	}
}
