package main

import (
	"testing"

	"github.com/noironetworks/cilium-net/bpf/lxcmap"

	. "github.com/noironetworks/cilium-net/Godeps/_workspace/src/gopkg.in/check.v1"
)

// Hook up gocheck into the "go test" runner.
func Test(t *testing.T) { TestingT(t) }

type BPFMapSuite struct {
}

var _ = Suite(&BPFMapSuite{})

func (s *BPFMapSuite) TestIsValidID(c *C) {
	m, err := lxcmap.ParseMAC("01:23:45:67:89:ab")
	c.Assert(err, Equals, nil)
	c.Assert(m, Equals, lxcmap.MAC(0xAB8967452301))
	c.Assert(m.String(), Equals, "01:23:45:67:89:AB")
	m, err = lxcmap.ParseMAC("FE:DC:BA:98:76:54")
	c.Assert(err, Equals, nil)
	c.Assert(m, Equals, lxcmap.MAC(0x547698BADCFE))
	c.Assert(m.String(), Equals, "FE:DC:BA:98:76:54")
}
