package common

import (
	. "github.com/noironetworks/cilium-net/Godeps/_workspace/src/gopkg.in/check.v1"
)

var _ = Suite(&CommonSuite{})

func (s *CommonSuite) TestGoArray2C(c *C) {
	c.Assert(GoArray2C([]byte{0, 0x01, 0x02, 0x03}), Equals, "{ 0x0, 0x1, 0x2, 0x3 }")
	c.Assert(GoArray2C([]byte{0, 0xFF, 0xFF, 0xFF}), Equals, "{ 0x0, 0xff, 0xff, 0xff }")
	c.Assert(GoArray2C([]byte{0xa, 0xbc, 0xde, 0xf1}), Equals, "{ 0xa, 0xbc, 0xde, 0xf1 }")
	c.Assert(GoArray2C([]byte{0}), Equals, "{ 0x0 }")
	c.Assert(GoArray2C([]byte{}), Equals, "{  }")
}

func (s *CommonSuite) TestFmtDefineAddress(c *C) {
	c.Assert(FmtDefineAddress("foo", []byte{1, 2, 3}), Equals, "#define foo { .addr = { 0x1, 0x2, 0x3 } }\n")
	c.Assert(FmtDefineAddress("foo", []byte{}), Equals, "#define foo { .addr = {  } }\n")
}

func (s *CommonSuite) TestfmtV6Prefix(c *C) {
	c.Assert(fmtV6Prefix("beef:", []byte{}), Equals, "<nil>")
	c.Assert(fmtV6Prefix("beef:", []byte{1, 2, 3, 4}), Equals, "beef::0102:0304:0")
}

func (s *CommonSuite) TestSwab16(c *C) {
	c.Assert(Swab16(0xAABB), Equals, uint16(0xBBAA),
		Commentf("Swab16 failed: Swab16(0xAABB) != 0xBBAA"))
}

func (s *CommonSuite) TestSwab32(c *C) {
	c.Assert(Swab32(0xAABBCCDD), Equals, uint32(0xDDCCBBAA),
		Commentf("Swab32 failed: Swab16(0xAABBCCDD) != 0xDDCCBBAA"))
}
