// Copyright 2021 Authors of Cilium
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

package utils

import (
	"testing"

	"gopkg.in/check.v1"
)

func Test(t *testing.T) {
	check.TestingT(t)
}

type UtilsSuite struct{}

var _ = check.Suite(&UtilsSuite{})

type failIfCalled struct {
	c *check.C
}

func (f *failIfCalled) Log(fmt string, args ...interface{}) {
	f.c.Error("log method should not be called")
}

type countIfCalled struct {
	count int
}

func (c *countIfCalled) Log(fmt string, args ...interface{}) {
	c.count++
}

func (b *UtilsSuite) TestExec(c *check.C) {
	_, err := Exec(&failIfCalled{c}, "true")
	c.Assert(err, check.IsNil)

	cl := &countIfCalled{0}
	_, err = Exec(cl, "false")
	c.Assert(err, check.Not(check.IsNil))
	c.Assert(cl.count, check.Equals, 1)

	cl.count = 0
	_, err = Exec(cl, "sh", "-c", "'echo foo; exit 1'")
	c.Assert(err, check.Not(check.IsNil))
	c.Assert(cl.count, check.Equals, 2)
}
