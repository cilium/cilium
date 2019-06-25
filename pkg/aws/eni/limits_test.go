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

package eni

import (
	"gopkg.in/check.v1"
)

func (e *ENISuite) TestGetLimits(c *check.C) {
	_, ok := GetLimits("unknown")
	c.Assert(ok, check.Equals, false)

	l, ok := GetLimits("m3.large")
	c.Assert(ok, check.Equals, true)
	c.Assert(l.Adapters, check.Not(check.Equals), 0)
	c.Assert(l.IPv4, check.Not(check.Equals), 0)
}
