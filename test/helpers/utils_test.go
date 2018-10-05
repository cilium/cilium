// Copyright 2017-2018 Authors of Cilium
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

package helpers

import (
	"testing"
	"time"

	. "gopkg.in/check.v1"
)

func Test(t *testing.T) { TestingT(t) }

type WithTimeoutTest struct{}

var _ = Suite(&WithTimeoutTest{})

func (s *WithTimeoutTest) TestTriggerErrorOnTimeout(c *C) {
	body := func() bool { return false }
	err := WithTimeout(body, "Error on timeout", &TimeoutConfig{
		Timeout: 3,
		Ticker:  1})
	c.Assert(err, NotNil)
}

func (s *WithTimeoutTest) TestTriggerCorrectlyActions(c *C) {
	n := 0
	body := func() bool {
		if n >= 3 {
			return true
		}
		n++
		return false
	}
	err := WithTimeout(body, "Error on timeout", &TimeoutConfig{
		Timeout: 5,
		Ticker:  1})
	c.Assert(err, IsNil)
	c.Assert(n, Equals, 3)
}

func (s *WithTimeoutTest) TestBlockingAction(c *C) {
	n := 0
	body := func() bool {
		n++
		time.Sleep(10 * time.Second)
		return false
	}
	err := WithTimeout(body, "Error on timeout", &TimeoutConfig{
		Timeout: 3,
		Ticker:  1})
	c.Assert(err, NotNil)

	c.Assert(n, Equals, 1)

}
