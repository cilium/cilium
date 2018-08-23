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

package ipcache

import (
	"testing"

	. "gopkg.in/check.v1"
)

// Hook up gocheck into the "go test" runner.
func Test(t *testing.T) {
	TestingT(t)
}

type IPCacheMapSuite struct{}

func (s *IPCacheMapSuite) TestSupportsDelete(c *C) {
	m := NewMap("foo")

	// m.supportsDelete will block until a deletion has occurred. Let's
	// make a delete "happen".
	close(m.deleteExecutedNotifier)

	// Should be able to execute multiple times
	c.Assert(m.supportsDelete, Equals, true)
	c.Assert(m.supportsDelete, Equals, true)

	close(m.deleteFailedNotifier)
	c.Assert(m.supportsDelete, Equals, false)
	c.Assert(m.supportsDelete, Equals, false)
}
