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

package regexpmap

import (
	"fmt"
	"regexp"
	"strings"
	"testing"

	. "gopkg.in/check.v1"
)

// Hook up gocheck into the "go test" runner.
func Test(t *testing.T) {
	TestingT(t)
}

type RegexpMapTestSuite struct{}

var _ = Suite(&RegexpMapTestSuite{})

func (ds *RegexpMapTestSuite) TestREMapInsertLookup(c *C) {
	// Can we compile and add entries
	m := NewRegexpMap()
	err := m.Add("foo.bar.com.", "ID1")
	c.Assert(err, IsNil, Commentf("Error compiling regex in map"))
	err = m.Add("foo.bar.com.", "ID2")
	c.Assert(err, IsNil, Commentf("Error compiling regex in map"))

	// Do we return the same entries we inserted
	keys := m.LookupValues("foo.bar.com.")
	c.Assert(len(keys), Equals, 2, Commentf("Incorrect number of values returned %v", keys))
	c.Assert(keys[0], Equals, "ID1", Commentf("Incorrect value returned"))
	c.Assert(keys[1], Equals, "ID2", Commentf("Incorrect value returned"))

	// Do we return nothing on no match
	keys = m.LookupValues("notabar.com.")
	c.Assert(len(keys), Equals, 0, Commentf("Returned values for non-match key %v", keys))

	// Does LookupValue match Added values internally?
	match := m.LookupContainsValue("foo.bar.com.", "ID1")
	c.Assert(match, Equals, true, Commentf("No match for key & value that should match"))
	match = m.LookupContainsValue("foo.bar.com.", "ID2")
	c.Assert(match, Equals, true, Commentf("No match for key & value that should match"))
	match = m.LookupContainsValue("foo.bar.com.", "ID3")
	c.Assert(match, Equals, false, Commentf("Match for key that matches & value that does not match"))
	match = m.LookupContainsValue("notabar.com.", "ID2")
	c.Assert(match, Equals, false, Commentf("Match for key that does not matche & value that does match"))

	// Does removing an entry also remove it from lookup returns
	m.Remove("foo.bar.com.", "ID1")
	keys = m.LookupValues("foo.bar.com.")
	c.Assert(len(keys), Equals, 1, Commentf("Incorrect number of values returned %v", keys))
	c.Assert(keys[0], Equals, "ID2", Commentf("Incorrect value returned"))

	// Do we crash on double removes, and will the map be empty after all keys are removed.
	m.Remove("foo.bar.com.", "ID1") // a no-op
	m.Remove("foo.bar.com.", "ID2")
	m.Remove("foo.bar.com.", "ID2") // a no-op
	keys = m.LookupValues("foo.bar.com.")
	c.Assert(len(keys), Equals, 0, Commentf("Incorrect number of values returned %v", keys))
}

func (ds *RegexpMapTestSuite) TestKeepUniqueStrings(c *C) {
	in := []string{"ID1", "ID2", "ID2"}
	out := keepUniqueStrings(in)
	for i, elem := range in[:2] {
		c.Assert(elem, Equals, out[i])
	}
}

func (ds *RegexpMapTestSuite) TestRefCount(c *C) {
	m := NewRegexpMap()
	domain := "foo.bar.com."
	endpoint := "ID1"

	m.Add(domain, endpoint)
	m.Add(domain, endpoint)

	c.Assert(m.lookups[domain][endpoint], Equals, 2)

	m.Remove(domain, endpoint)

	c.Assert(m.lookups[domain][endpoint], Equals, 1)

	m.Remove(domain, endpoint)
	_, found := m.lookups[domain]

	c.Assert(found, Equals, false)
}

//  reSize is the number of distinct subpatterns/regexes to benchmark with
var reSize = 100

func (ds *RegexpMapTestSuite) BenchmarkRegexSingle(c *C) {
	c.StopTimer()
	re := regexp.MustCompile("(?P<iter_>bar.foo.com.)")
	in := []byte("bar.foo.com.")
	c.StartTimer()
	for i := c.N; i > 0; i-- {
		re.FindSubmatchIndex(in)
	}
}

func (ds *RegexpMapTestSuite) BenchmarkRegexLinearSearch(c *C) {
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

func (ds *RegexpMapTestSuite) BenchmarkRegexGroups(c *C) {
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
