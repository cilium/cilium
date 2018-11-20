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

package fqdn

import (
	. "gopkg.in/check.v1"
)

func (ds *FQDNTestSuite) TestSimpleFQDN(c *C) {
	for _, name := range []string{
		"foo.com.",
		"FoO.CoM.",
		"FOO.COM.",
		"foo-bar.com.",
		"-foo-bar.com.", // a leading '-' is probably illegal
		"-foo-bar.com.",
		"com.", // illegal but we consider it simple
	} {
		c.Assert(isSimpleFQDN(name), Equals, true, Commentf("Simple FQDN incorrectly identified as not simple: %s", name))
	}

	for _, name := range []string{
		"*goo.com",
		"[a-z].com",
		".{1,3}com",
		"*GoO.com",
		`foo\.com\.`, // a literal string to make the \ more clear
	} {
		c.Assert(isSimpleFQDN(name), Equals, false, Commentf("Not-simple FQDN incorrectly identified as simple: %s", name))
	}
}
