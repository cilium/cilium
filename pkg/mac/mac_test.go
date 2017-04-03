// Copyright 2016-2017 Authors of Cilium
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

package mac

import (
	"encoding/json"
	"testing"

	. "gopkg.in/check.v1"
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
	c.Assert(v, Equals, uint64(0x564534231211))
}

func (s *MACSuite) TestUnmarshalJSON(c *C) {
	m := MAC([]byte{0x11, 0x12, 0x23, 0x34, 0x45, 0x56})
	w := MAC([]byte{0x11, 0x12, 0x23, 0x34, 0x45, 0xAB})
	d, err := json.Marshal(m)
	c.Assert(err, IsNil)
	c.Assert(d, DeepEquals, []byte(`"11:12:23:34:45:56"`))
	var t MAC
	err = json.Unmarshal([]byte(`"11:12:23:34:45:AB"`), &t)
	c.Assert(err, IsNil)
	c.Assert(t, DeepEquals, w)
	err = json.Unmarshal([]byte(`"11:12:23:34:45:A"`), &t)
	c.Assert(err, NotNil)

	m = MAC([]byte{})
	w = MAC([]byte{})
	d, err = json.Marshal(m)
	c.Assert(err, Equals, nil)
	c.Assert(d, DeepEquals, []byte(`""`))
	var t2 MAC
	err = json.Unmarshal([]byte(`""`), &t2)
	c.Assert(err, IsNil)
	c.Assert(t2, DeepEquals, w)
}
