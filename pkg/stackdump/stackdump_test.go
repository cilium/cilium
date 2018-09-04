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

package stackdump

import (
	"bufio"
	"bytes"
	"strings"
	"testing"

	. "gopkg.in/check.v1"
)

func Test(t *testing.T) {
	TestingT(t)
}

type StackDumpTestSuite struct{}

var _ = Suite(&StackDumpTestSuite{})

func (s *StackDumpTestSuite) TestStackDump(c *C) {
	var buf bytes.Buffer
	w := bufio.NewWriter(&buf)
	Fprintf(w, "test message")
	w.Flush()
	c.Assert(strings.Contains(buf.String(), "github.com/cilium/cilium/pkg/stackdump.Fprintf"), Equals, true)
}

func (s *StackDumpTestSuite) TestDebugPanicf(c *C) {
	DebugPanicf("test panic message: %d", 10)
}
