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

package alignchecker

import (
	"reflect"
	"testing"

	. "gopkg.in/check.v1"
)

type AlignCheckerSuite struct{}

var _ = Suite(&AlignCheckerSuite{})

func Test(t *testing.T) {
	TestingT(t)
}

const path = "testdata/bpf_foo.o"

type foo struct {
	ipv6 [4]uint32 `align:"$union0"`
	misc uint32    `align:"$union1"`
	f    uint8     `align:"family"`
	pad4 uint8     `align:"pad4"`
	pad5 uint16    `align:"pad5"`
}

type fooInvalidSize struct {
	ipv6 uint32
}

type fooInvalidOffset struct {
	ipv6 [4]uint32 `align:"$union0"`
	misc uint32    `align:"$union1"`
	f    uint16    `align:"family"`
	pad4 uint8     `align:"pad4"`
	pad5 uint8     `align:"pad5"`
}

type toCheck map[string]reflect.Type

func (t *AlignCheckerSuite) TestCheckStructAlignments(c *C) {
	err := CheckStructAlignments(path, toCheck{"foo": reflect.TypeOf(foo{})})
	c.Assert(err, IsNil)

	err = CheckStructAlignments(path, toCheck{"foo": reflect.TypeOf(fooInvalidSize{})})
	c.Assert(err, ErrorMatches,
		`*.fooInvalidSize\(4\) size does not match foo\(24\)`)

	err = CheckStructAlignments(path, toCheck{"foo": reflect.TypeOf(fooInvalidOffset{})})
	c.Assert(err, ErrorMatches,
		`*.fooInvalidOffset.pad4 offset\(22\) does not match foo.pad4\(21\)`)

	err = CheckStructAlignments(path, toCheck{"bar": reflect.TypeOf(foo{})})
	c.Assert(err, ErrorMatches, "C struct bar not found")
}
