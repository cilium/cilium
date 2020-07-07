// Copyright 2020 Authors of Cilium
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

package constchecker

import (
	"reflect"
	"testing"

	"github.com/cilium/cilium/pkg/checker"

	. "gopkg.in/check.v1"
)

type ConstSuite struct{}

var _ = Suite(&ConstSuite{})

func Test(t *testing.T) {
	TestingT(t)
}

func (t *ConstSuite) TestCheckConstsOk(c *C) {
	const foo = uint8(23)
	const bar = uint64(12345678)
	toCheck := map[string]reflect.Value{
		"foo_const": reflect.ValueOf(foo),
		"bar_const": reflect.ValueOf(bar),
	}

	CheckEnv(c, toCheck)
}

func (t *ConstSuite) TestCheckConstsSizeMismatch(c *C) {
	const foo = uint16(23)
	toCheck := map[string]reflect.Value{
		"foo_const": reflect.ValueOf(foo),
	}
	err := CheckEnvErr(c, toCheck)
	c.Assert(err, checker.DeepEquals, &ErrSizeMismatch{Name: "foo_const", SizeBpf: 1, SizeVal: 2})
}

func (t *ConstSuite) TestCheckConstsValueMismatch(c *C) {
	const foo = uint8(22)
	toCheck := map[string]reflect.Value{
		"foo_const": reflect.ValueOf(foo),
	}
	err := CheckEnvErr(c, toCheck)
	c.Assert(err, checker.DeepEquals, &ErrValueMismatch{Name: "foo_const", ValBpf: reflect.ValueOf(uint8(23)), Val: reflect.ValueOf(foo)})
}

func (t *ConstSuite) TestCheckConstsValueNotFound(c *C) {
	const foo = uint8(22)
	toCheck := map[string]reflect.Value{
		"pizza": reflect.ValueOf(foo),
	}
	err := CheckEnvErr(c, toCheck)
	c.Assert(err, ErrorMatches, "error for symbol pizza: does not exist")
}
