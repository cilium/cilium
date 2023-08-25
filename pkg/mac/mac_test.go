// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package mac

import (
	"encoding/json"
	"testing"

	. "github.com/cilium/checkmate"

	"github.com/cilium/cilium/pkg/checker"
)

// Hook up gocheck into the "go test" runner.
func Test(t *testing.T) {
	TestingT(t)
}

type MACSuite struct{}

var _ = Suite(&MACSuite{})

func (s *MACSuite) TestUint64(c *C) {
	m := MAC([]byte{0x11, 0x12, 0x23, 0x34, 0x45, 0x56})
	v, err := m.Uint64()
	c.Assert(err, IsNil)
	c.Assert(v, Equals, Uint64MAC(0x564534231211))
}

func (s *MACSuite) TestUnmarshalJSON(c *C) {
	m := MAC([]byte{0x11, 0x12, 0x23, 0x34, 0x45, 0x56})
	w := MAC([]byte{0x11, 0x12, 0x23, 0x34, 0x45, 0xAB})
	d, err := json.Marshal(m)
	c.Assert(err, IsNil)
	c.Assert(d, checker.DeepEquals, []byte(`"11:12:23:34:45:56"`))
	var t MAC
	err = json.Unmarshal([]byte(`"11:12:23:34:45:AB"`), &t)
	c.Assert(err, IsNil)
	c.Assert(t, checker.DeepEquals, w)
	err = json.Unmarshal([]byte(`"11:12:23:34:45:A"`), &t)
	c.Assert(err, NotNil)

	m = MAC([]byte{})
	w = MAC([]byte{})
	d, err = json.Marshal(m)
	c.Assert(err, Equals, nil)
	c.Assert(d, checker.DeepEquals, []byte(`""`))
	var t2 MAC
	err = json.Unmarshal([]byte(`""`), &t2)
	c.Assert(err, IsNil)
	c.Assert(t2, checker.DeepEquals, w)
}
