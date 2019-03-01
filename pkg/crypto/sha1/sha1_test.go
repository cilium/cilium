// Copyright 2019 Authors of Cilium
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

// +build !privileged_tests

package sha1

import (
	"math/rand"
	"testing"

	"github.com/cilium/cilium/pkg/checker"

	. "gopkg.in/check.v1"
)

// Hook up gocheck into the "go test" runner.
type Sha1TestSuite struct{}

var _ = Suite(&Sha1TestSuite{})

func Test(t *testing.T) {
	TestingT(t)
}

func (s *Sha1TestSuite) TestCopy(c *C) {
	input := make([]byte, 256)
	_, err := rand.Read(input)
	c.Assert(err, IsNil)

	h1 := New()
	h1.Write(input)
	h2 := New()
	h2.Write(input)
	c.Assert(h1, checker.DeepEquals, h2)
	c.Assert(h1.String(), Equals, h2.String())

	h2.Write(input)
	c.Assert(h1.String(), Not(Equals), h2.String())
}
