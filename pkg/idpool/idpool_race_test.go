// Copyright 2018-2020 Authors of Cilium
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

// +build !privileged_tests,race

package idpool

import (
	. "gopkg.in/check.v1"
)

// TestAllocateID without the race detection enabled is too slow to run with
// race detector set. Thus, we need to put it in a separate file so the unit
// tests don't time out while running with race detector by having a lower
// number of parallel go routines than it would have been if we ran it without
// the race detector.
func (s *IDPoolTestSuite) TestAllocateID(c *C) {
	s.testAllocatedID(c, 5)
}
