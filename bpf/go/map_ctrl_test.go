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
package main

import (
	"testing"

	"github.com/noironetworks/cilium-net/bpf/lxcmap"

	. "gopkg.in/check.v1"
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
