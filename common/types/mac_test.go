package types

import (
	. "github.com/noironetworks/cilium-net/Godeps/_workspace/src/gopkg.in/check.v1"
)

// Hook up gocheck into the "go test" runner.
type MACSuite struct{}

var _ = Suite(&MACSuite{})

func (s *MACSuite) TestUint64(c *C) {
	m := MAC([]byte{0x11, 0x12, 0x23, 0x34, 0x45, 0x56})
	v, err := m.Uint64()
	c.Assert(err, Equals, nil)
	c.Assert(v, Equals, uint64(0x564534231211))
}
