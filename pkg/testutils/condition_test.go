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

package testutils

import (
	"time"

	. "gopkg.in/check.v1"
)

func (s *TestUtilsSuite) TestCondition(c *C) {
	c.Assert(WaitUntil(func() bool { return false }, 50*time.Millisecond), Not(IsNil))
	c.Assert(WaitUntil(func() bool { return true }, 50*time.Millisecond), IsNil)

	counter := 0
	countTo5 := func() bool {
		if counter > 5 {
			return true
		}
		counter++
		return false
	}

	c.Assert(WaitUntil(countTo5, 1*time.Millisecond), Not(IsNil))

	counter = 0
	c.Assert(WaitUntil(countTo5, 100*time.Millisecond), IsNil)
}
