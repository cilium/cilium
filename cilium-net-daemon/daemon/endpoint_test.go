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
