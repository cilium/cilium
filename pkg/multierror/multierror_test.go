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

package multierror

import (
	"errors"
	"testing"

	. "gopkg.in/check.v1"
)

// Hook up gocheck into the "go test" runner.
type MultierrorTestSuite struct{}

var _ = Suite(&MultierrorTestSuite{})

func Test(t *testing.T) {
	TestingT(t)
}

func (s *MultierrorTestSuite) TestMultierrorEmpty(c *C) {
	errs := &Multierror{}
	c.Assert(errs.Error(), Equals, "")
}

func (s *MultierrorTestSuite) TestMultierrorOneElement(c *C) {
	var errs *Multierror
	errs = Append(errs, errors.New("foo"))
	c.Assert(errs.Error(), Equals, "foo")
}

func (s *MultierrorTestSuite) TestMultierror(c *C) {
	var errs *Multierror

	errs = Append(errs, errors.New("foo"))
	errs = Append(errs, errors.New("bar"))
	errs = Append(errs, errors.New("ayy"))
	errs = Append(errs, errors.New("lmao"))

	c.Assert(errs.Error(), Equals, "foo; bar; ayy; lmao")
}
