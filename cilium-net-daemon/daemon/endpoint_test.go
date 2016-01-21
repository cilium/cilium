package daemon

import (
	"testing"

	. "github.com/noironetworks/cilium-net/Godeps/_workspace/src/gopkg.in/check.v1"
)

// Hook up gocheck into the "go test" runner.
func Test(t *testing.T) { TestingT(t) }

type DaemonSuite struct {
}

var _ = Suite(&DaemonSuite{})

func (s *DaemonSuite) TestIsValidID(c *C) {
	c.Assert(isValidID("1"), Equals, true)
	c.Assert(isValidID("0"), Equals, true)
	c.Assert(isValidID(""), Equals, false)
	c.Assert(isValidID("./1142"), Equals, false)
	c.Assert(isValidID("121212"), Equals, true)
	c.Assert(isValidID("1212121111111111111111"), Equals, true)
	c.Assert(isValidID("-"), Equals, false)
	c.Assert(isValidID("-123"), Equals, false)
	c.Assert(isValidID("0x12"), Equals, false)
	c.Assert(isValidID("./../../../etc"), Equals, false)
}

func (s *DaemonSuite) TestGoArray2C(c *C) {
	c.Assert(goArray2C([]byte{0, 0x01, 0x02, 0x03}), Equals, "{ 0x0, 0x1, 0x2, 0x3 }")
	c.Assert(goArray2C([]byte{0, 0xFF, 0xFF, 0xFF}), Equals, "{ 0x0, 0xff, 0xff, 0xff }")
	c.Assert(goArray2C([]byte{0xa, 0xbc, 0xde, 0xf1}), Equals, "{ 0xa, 0xbc, 0xde, 0xf1 }")
	c.Assert(goArray2C([]byte{0}), Equals, "{ 0x0 }")
	c.Assert(goArray2C([]byte{}), Equals, "{  }")
}
