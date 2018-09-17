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

package regexpmap

import (
	"fmt"
	"regexp"
	"strings"

	. "gopkg.in/check.v1"
)

func (ds *FQDNTestSuite) TestREMapInsertLookup(c *C) {
	m := NewRegexpMap()
	err := m.Add("foo.bar.com.", "ID1")
	c.Assert(err, IsNil, Commentf("Error compiling regex in map"))
	err = m.Add("foo.bar.com.", "ID2")
	c.Assert(err, IsNil, Commentf("Error compiling regex in map"))

	keys := m.Lookup("foo.bar.com.")
	c.Assert(len(keys), Equals, 2, Commentf("Incorrect number of values returned %v", keys))
	c.Assert(keys[0], Equals, "ID1", Commentf("Incorrect value returned"))
	c.Assert(keys[1], Equals, "ID2", Commentf("Incorrect value returned"))

	m.Remove("foo.bar.com.", "ID1")
	keys = m.Lookup("foo.bar.com.")
	c.Assert(len(keys), Equals, 1, Commentf("Incorrect number of values returned %v", keys))
	c.Assert(keys[0], Equals, "ID2", Commentf("Incorrect value returned"))

	m.Remove("foo.bar.com.", "ID1") // a no-op
	m.Remove("foo.bar.com.", "ID2")
	keys = m.Lookup("foo.bar.com.")
	c.Assert(len(keys), Equals, 0, Commentf("Incorrect number of values returnedi %v", keys))
}

func (ds *FQDNTestSuite) TestKeepUniqueStrings(c *C) {
	in := []string{"ID1", "ID2", "ID2"}
	out := keepUniqueStrings(in)
	for i, elem := range in[:2] {
		c.Assert(elem, Equals, out[i])
	}
}

//  reSize is the number of distinct subpatterns/regexes to benchmark with
var reSize = 100

func (ds *FQDNTestSuite) BenchmarkRegexSingle(c *C) {
	c.StopTimer()
	re := regexp.MustCompile("(?P<iter_>bar.foo.com.)")
	in := []byte("bar.foo.com.")
	c.StartTimer()
	for i := c.N; i > 0; i-- {
		re.FindSubmatchIndex(in)
	}
}

func (ds *FQDNTestSuite) BenchmarkRegexLinearSearch(c *C) {
	c.StopTimer()
	m := map[*regexp.Regexp]int{}
	for i := reSize; i > 0; i-- {
		m[regexp.MustCompile("bar.foo.com.")] = i
	}
	in := []byte("bar.foo.com.")
	c.StartTimer()
	for i := c.N; i > 0; i-- {
		for re := range m {
			re.FindSubmatchIndex(in)
		}
	}
}

func (ds *FQDNTestSuite) BenchmarkRegexGroups(c *C) {
	c.StopTimer()
	elements := []string{}
	var re *regexp.Regexp
	for i := reSize; i > 0; i-- {
		elements = append(elements, fmt.Sprintf("(?P<iter_%d>bar.foo.com.)", i))
	}
	re = regexp.MustCompile("^" + strings.Join(elements, "|") + "$")

	in := []byte("bar.foo.com.")
	c.StartTimer()

	for i := c.N; i > 0; i-- {
		re.FindSubmatchIndex(in)
	}
}
