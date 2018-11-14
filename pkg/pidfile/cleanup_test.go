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

// +build !privileged_tests

package pidfile

import (
	"sync"

	. "gopkg.in/check.v1"
)

func (pfs *PidfileTestSuite) TestHandleCleanup(c *C) {
	wg := &sync.WaitGroup{}
	ch := make(chan struct{})
	i := 0
	HandleCleanup(wg, ch, func() {
		i++
	})
	close(ch)
	wg.Wait()
	c.Assert(i, Equals, 1)
}
