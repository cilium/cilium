package main

import (
	"testing"

	. "github.com/noironetworks/cilium-net/Godeps/_workspace/src/gopkg.in/check.v1"
)

// Hook up gocheck into the "go test" runner.
func Test(t *testing.T) { TestingT(t) }

type BPFMapSuite struct {
}

var _ = Suite(&BPFMapSuite{})

func (s *BPFMapSuite) TestIsValidID(c *C) {
	m, err := ParseMAC("01:23:45:67:89:ab")
	c.Assert(err, Equals, nil)
	c.Assert(m, Equals, mac(0x0123456789ab))
	c.Assert(m.String(), Equals, "01:23:45:67:89:AB")
	m, err = ParseMAC("FE:DC:BA:98:76:54")
	c.Assert(err, Equals, nil)
	c.Assert(m, Equals, mac(0xFEDCBA987654))
	c.Assert(m.String(), Equals, "FE:DC:BA:98:76:54")
}
