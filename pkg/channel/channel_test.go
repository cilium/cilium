// Copyright 2018 Authors of Cilium
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

package channel

import (
	"testing"

	. "gopkg.in/check.v1"
)

// Hook up gocheck into the "go test" runner.
func Test(t *testing.T) {
	TestingT(t)
}

type ChannelSuite struct{}

func (s *ChannelSuite) TestIsOpenB(c *C) {
	channel := make(chan bool)

	res, open := ReadB(channel)
	c.Assert(open, Equals, true)
	c.Assert(IsOpenB(channel), Equals, true)
	c.Assert(res, IsNil)

	channel <- true
	res, open = ReadB(channel)
	c.Assert(open, Equals, true)
	c.Assert(res, NotNil)
	// Note this occurs *after* the ReadB(), so it will not lose the value.
	c.Assert(IsOpenB(channel), Equals, true)

	CloseB(channel)
	res, open = ReadB(channel)
	c.Assert(open, Equals, false)
	c.Assert(IsOpenB(channel), Equals, false)
	c.Assert(res, IsNil)
}
